package dependencycheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	models "vulnerability-management/internal/pkg/models/findings"
	tool_models "vulnerability-management/internal/pkg/models/tool-types"
)

type Vulnerability struct {
	XMLName     xml.Name    `xml:"vulnerability"`
	Name        string      `xml:"name"`
	CWEs        CWEs        `xml:"cwes"`
	Description string      `xml:"description"`
	Source      string      `xml:"source,attr"`
	Notes       string      `xml:"notes"`
	CVSSv2      *CVSS       `xml:"cvssV2"`
	CVSSv3      *CVSS       `xml:"cvssV3"`
	Severity    string      `xml:"severity"`
	References  []Reference `xml:"references>reference"`
}

// Define the CWE structure
type CWE struct {
	Text string `xml:",chardata"`
}

// Define the CWEs structure containing multiple CWE elements
type CWEs struct {
	CWEs []CWE `xml:"cwe"`
}

type CVSS struct {
	BaseSeverity string `xml:"baseSeverity"`
	Severity     string `xml:"severity"`
}

type Reference struct {
	Source string `xml:"source"`
	URL    string `xml:"url"`
	Name   string `xml:"name"`
}

type Scan struct {
	XMLName      xml.Name     `xml:"analysis"`
	Dependencies []Dependency `xml:"dependencies>dependency"`
	ProjectInfo  ProjectInfo  `xml:"projectInfo"`
}

type Dependency struct {
	XMLName           xml.Name            `xml:"dependency"`
	FileName          string              `xml:"fileName"`
	FilePath          string              `xml:"filePath"`
	Vulnerabilities   []Vulnerability     `xml:"vulnerabilities>vulnerability"`
	RelatedDeps       []RelatedDependency `xml:"relatedDependencies>relatedDependency"`
	Identifiers       Identifiers         `xml:"identifiers"`
	EvidenceCollected EvidenceCollected   `xml:"evidenceCollected"`
}

type Identifiers struct {
	XMLName xml.Name `xml:"identifiers"`
	Package Package  `xml:"package"`
}

type Package struct {
	Confidence string `xml:"confidence,attr"`
	ID         string `xml:"id"`
	URL        string `xml:"url"`
}

type EvidenceCollected struct {
	XMLName   xml.Name   `xml:"evidenceCollected"`
	Evidences []Evidence `xml:"evidence"`
}

type Evidence struct {
	Type       string `xml:"type,attr"`
	Confidence string `xml:"confidence,attr"`
	Source     string `xml:"source"`
	Name       string `xml:"name"`
	Value      string `xml:"value"`
}

type RelatedDependency struct {
	XMLName  xml.Name `xml:"relatedDependency"`
	FileName string   `xml:"fileName"`
	FilePath string   `xml:"filePath"`
	SHA256   string   `xml:"sha256"`
	SHA1     string   `xml:"sha1"`
	MD5      string   `xml:"md5"`
}

type ProjectInfo struct {
	ReportDate string `xml:"reportDate"`
}
type DependencyCheck struct{}

func (p *DependencyCheck) Parser(toolInfo tool_models.ToolInfo) ([]models.Finding, error) {
	log.Info().Msgf("Parser DependencyCheck")
	findings, err := getFindings(toolInfo.ReportFile)
	if err != nil {
		log.Error().Msgf(err.Error())
	}

	// for _, finding := range findings {
	// 	log.Info().Msgf(finding.Title)
	// }
	return findings, nil
}

func (p *DependencyCheck) GetToolTypes() string {
	return "DependencyCheck"
}

func (p *DependencyCheck) RequiresFile() bool {
	return true
}

func getFindings(filename string) ([]models.Finding, error) {
	dupes := make(map[string]models.Finding)

	// Open our xmlFile
	xmlFile, err := os.Open(filename)
	if err != nil {
		log.Error().Msgf("Open our xmlFile" + err.Error())
	}

	log.Info().Msgf("Successfully Opened users.xml")
	// defer the closing of our xmlFile so that we can parse it later on
	defer xmlFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, _ := io.ReadAll(xmlFile)

	var scan Scan
	err = xml.Unmarshal(byteValue, &scan)

	if err != nil {
		log.Error().Msgf("Error unmarshalling XML: %v" + err.Error())
	}

	var scanDate time.Time
	if scan.ProjectInfo.ReportDate != "" {
		scanDate, err = time.Parse(time.RFC3339, scan.ProjectInfo.ReportDate)
		if err != nil {
			log.Error().Msgf("Error parsing date: %v" + err.Error())
		}
	}

	log.Info().Msgf("ScanDate %s", scanDate)

	for _, dependency := range scan.Dependencies {
		for _, vulnerability := range dependency.Vulnerabilities {
			// fmt.Print(vulnerability)
			finding, err := getFindingFromVulnerability(dependency, nil, vulnerability)
			if err != nil {
				log.Error().Msgf("Error get Finding: %v", err)
			}
			addFinding(finding, dupes)
		}
	}

	var findings []models.Finding
	for _, finding := range dupes {
		findings = append(findings, finding)
	}

	return findings, nil
}

func getFindingFromVulnerability(dependency Dependency, relatedDependency *Dependency, vulnerability Vulnerability) (models.Finding, error) {
	dependencyFilename, dependencyFilepath := getFilenameAndPathFromDependency(dependency, relatedDependency)

	if dependencyFilename == "" {
		return models.Finding{}, fmt.Errorf("getFindingFromVulnerability: %s", "Not Found File")
	}
	name := vulnerability.Name

	var cweField string
	if len(vulnerability.CWEs.CWEs) > 0 {
		cweField = vulnerability.CWEs.CWEs[0].Text
	}

	description := vulnerability.Description
	vulnID := ""
	source := vulnerability.Source
	if source != "" {
		description += "\n**Source:** " + source

	}
	if source == "NVD" {
		vulnID = name
	}

	cwe := 1035
	if cweField != "" {
		re := regexp.MustCompile(`^(CWE-)?(\d+)`)
		matches := re.FindStringSubmatch(cweField)
		if len(matches) > 2 {
			cwe = toInt(matches[2])
		}
	}

	severity := vulnerability.Severity
	if severity == "" {
		if vulnerability.CVSSv3.BaseSeverity != "" {
			severity = strings.Title(strings.ToLower(vulnerability.CVSSv3.BaseSeverity))
		} else if vulnerability.CVSSv2.Severity != "" {
			severity = strings.Title(strings.ToLower(vulnerability.CVSSv2.Severity))
		}
	}

	var referenceDetail string
	if len(vulnerability.References) > 0 {
		referenceDetail = ""
		for _, ref := range vulnerability.References {
			if ref.URL == ref.Name {
				referenceDetail += fmt.Sprintf("**Source:** %s\n**URL:** %s\n\n", ref.Source, ref.URL)
			} else {
				referenceDetail += fmt.Sprintf("**Source:** %s\n**URL:** %s\n**Name:** %s\n\n", ref.Source, ref.URL, ref.Name)
			}
		}
	}

	var active bool

	componentName, componentVersion := getComponentNameAndVersionFromDependency(dependency)
	mitigation := fmt.Sprintf("Update %s:%s to at least the version recommended in the description", componentName, componentVersion)
	description += "\n**Filepath:** " + dependencyFilepath
	active = true

	finding := &models.Finding{
		Title:    fmt.Sprintf("%s:%s | %s", componentName, componentVersion, name),
		FilePath: dependencyFilename,
		// TestID:          test,
		VulnIDFromTool: vulnID,
		CWE:            uint64(cwe),
		Description:    description,
		Severity:       mapSeverity(severity),
		Mitigation:     mitigation,
		Active:         active,
		DynamicFinding: false,
		StaticFinding:  true,
		Reference:      referenceDetail,
	}

	return *finding, nil
}

func toInt(str string) int {
	val, err := strconv.Atoi(str)
	if err != nil {
		return 0
	}
	return val
}

func mapSeverity(severity string) uint64 {
	severityMapping := map[string]uint64{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      1,
		"info":     0,
	}
	if val, ok := severityMapping[strings.ToLower(severity)]; ok {
		return val
	}
	log.Warn().Msgf("Warning: Unknown severity value detected '%s'. Bypass to 'Medium' value", severity)
	return 3
}

func getFilenameAndPathFromDependency(dependency Dependency, relatedDependency *Dependency) (string, string) {
	if relatedDependency == nil {
		return dependency.FileName, dependency.FilePath
	}
	if relatedDependency.FileName != "" {
		return relatedDependency.FileName, relatedDependency.FilePath
	} else {
		return "", ""
	}
}

func addFinding(finding models.Finding, dupes map[string]models.Finding) {
	keyStr := strings.Join([]string{
		finding.Title,
		strconv.Itoa(int(finding.CWE)),
		strings.ToLower(finding.FilePath),
	}, "|")

	hash := sha256.New()
	hash.Write([]byte(keyStr))
	key := hex.EncodeToString(hash.Sum(nil))

	if _, exists := dupes[key]; !exists {
		dupes[key] = finding
	}
}

func getComponentNameAndVersionFromDependency(dependency Dependency) (string, string) {
	var componentName, componentVersion string

	if dependency.Identifiers.Package.ID != "" {
		purl, err := packageurl.FromString(dependency.Identifiers.Package.ID)
		// fmt.Println(purl)
		if err == nil {

			componentName := purl.Name
			componentVersion := purl.Version

			return componentName, componentVersion
		}
	}

	for _, evidence := range dependency.EvidenceCollected.Evidences {
		if evidence.Type == "product" {
			componentName = evidence.Value
		}
		if evidence.Type == "version" {
			componentVersion = evidence.Value
		}
	}

	if componentName == "" {
		componentName = "UnknownComponent"
	}
	if componentVersion == "" {
		componentVersion = "UnknownVersion"
	}
	return componentName, componentVersion
}
