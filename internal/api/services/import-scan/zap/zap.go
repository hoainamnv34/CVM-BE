package zap

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	models "vulnerability-management/internal/pkg/models/findings"
)

type Scan struct {
	XMLName xml.Name `xml:"OWASPZAPReport"`
	Site    Site     `xml:"site"`
}

type Site struct {
	XMLName xml.Name    `xml:"site"`
	Alerts  []AlertItem `xml:"alerts>alertitem"`
}

type AlertItem struct {
	XMLName     xml.Name   `xml:"alertitem"`
	Alert       string     `xml:"alert"`
	Description string     `xml:"desc"`
	RiskCode    string     `xml:"riskcode"`
	Solution    string     `xml:"solution"`
	Reference   string     `xml:"reference"`
	Dynamic     string     `xml:"dynamic"`
	Static      string     `xml:"static"`
	PluginID    string     `xml:"pluginid"`
	CWEID       string     `xml:"cweid"`
	Instances   []Instance `xml:"instances>instance"`
}

type Instance struct {
	XMLName        xml.Name `xml:"instance"`
	URI            string   `xml:"uri"`
	RequestHeader  string   `xml:"requestheader"`
	RequestBody    string   `xml:"requestbody"`
	ResponseHeader string   `xml:"responseheader"`
	ResponseBody   string   `xml:"responsebody"`
}

type Zap struct{}

func (p *Zap) Parser(filename string, servicekey string) ([]models.Finding, error) {
	fmt.Println("import Zap")
	findings, err := getFindings(filename)
	if err != nil {
		fmt.Println("looi1")
	}

	for _, finding := range findings {
		fmt.Println("Hi")
		fmt.Println(finding.Title)
	}
	return findings, nil
}

func (p *Zap) GetToolTypes() string {
	return "Zap"
}

func (p *Zap) RequiresFile() bool {
	return true
}

func getFindings(filename string) ([]models.Finding, error) {
	items := []models.Finding{}

	// Open our xmlFile
	xmlFile, err := os.Open(filename)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Successfully Opened users.xml")
	// defer the closing of our xmlFile so that we can parse it later on
	defer xmlFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, _ := io.ReadAll(xmlFile)

	var scan Scan

	err = xml.Unmarshal(byteValue, &scan)
	if err != nil {
		return nil, err
	}

	for _, alertItem := range scan.Site.Alerts {
		finding := models.Finding{
			// TestID:          test,
			Title:           alertItem.Alert,
			RiskDescription: html2text(alertItem.Description),
			Severity:        mapSeverity(alertItem.RiskCode),
			Mitigation:      html2text(alertItem.Solution),
			Reference:       html2text(alertItem.Reference),
			DynamicFinding:  true,
			StaticFinding:   false,
			VulnIDFromTool:  alertItem.PluginID,
		}

		if cweID := alertItem.CWEID; cweID != "" && strings.Contains(cweID, "CWE-") {
			finding.CWE = parseCWEID(cweID)
		}

		// finding.UnsavedEndpoints = make([]Endpoint, 0)
		// finding.UnsavedReqResp = make([]map[string]string, 0)

		// for _, instance := range alertItem.Instances.Instance {
		// 	endpoint := NewEndpoint(instance.URI)

		// 	request := instance.RequestHeader + instance.RequestBody
		// 	response := instance.ResponseHeader + instance.ResponseBody

		// 	finding.UnsavedEndpoints = append(finding.UnsavedEndpoints, endpoint)
		// 	finding.UnsavedReqResp = append(finding.UnsavedReqResp, map[string]string{
		// 		"req":  request,
		// 		"resp": response,
		// 	})
		// }

		items = append(items, finding)
	}

	return items, nil
}

func html2text(html string) string {
	// Implement html to text conversion if needed
	return html // Placeholder function, needs implementation
}

func parseCWEID(cweID string) uint64 {
	cweID = strings.TrimSpace(cweID)
	if cweID == "" {
		return 0 // Return 0 or handle error as per your requirement
	}

	id, err := strconv.ParseUint(cweID, 10, 64)
	if err != nil {
		fmt.Println("Error parsing CWE ID:", err)
		return 0 // Return 0 or handle error as per your requirement
	}

	return id
}

func mapSeverity(severity string) uint64 {
	severityMapping := map[string]uint64{
		"3": 4, //High
		"2": 3, //Medium
		"1": 2, //Low
		"0": 1, //Info
	}
	if val, ok := severityMapping[strings.ToLower(severity)]; ok {
		return val
	}
	log.Printf("Warning: Unknown severity value detected '%s'. Bypass to 'Medium' value", severity)
	return 3
}
