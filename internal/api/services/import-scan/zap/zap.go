package zap

import (
	"encoding/xml"
	"io"
	"os"
	"strconv"
	"strings"
	models "vulnerability-management/internal/pkg/models/findings"
	tool_models "vulnerability-management/internal/pkg/models/tool-types"

	"github.com/rs/zerolog/log"
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

func (p *Zap) Parser(toolInfo tool_models.ToolInfo) ([]models.Finding, error) {
	log.Info().Msgf("Parser Zap")
	findings, err := getFindings(toolInfo.ReportFile)
	if err != nil {
		log.Error().Msgf(err.Error())
		return nil, err
	}

	// for _, finding := range findings {
	// 	log.Info().Msgf(finding.Title)
	// }
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
		log.Error().Msgf("open file error")
		return nil, err
	}

	log.Info().Msgf("Successfully Opened users.xml")
	// defer the closing of our xmlFile so that we can parse it later on
	defer xmlFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, _ := io.ReadAll(xmlFile)

	var scan Scan

	err = xml.Unmarshal(byteValue, &scan)
	if err != nil {
		return nil, err
	}

	var cwe uint64
	for _, alertItem := range scan.Site.Alerts {

		a, err := stringToUint64(alertItem.CWEID)

		if err != nil {
			cwe = 0
		} else {
			cwe = a
		}

		finding := models.Finding{
			Title:          alertItem.Alert,
			Description:    html2text(alertItem.Description),
			Severity:       mapSeverity(alertItem.RiskCode),
			Mitigation:     html2text(alertItem.Solution),
			Reference:      html2text(alertItem.Reference),
			Active:         true,
			DynamicFinding: true,
			StaticFinding:  false,
			VulnIDFromTool: alertItem.PluginID,
			CWE:            cwe,
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

		//check duplicate
		isDuplicate := false
		for _, item := range items {
			if item.Title == finding.Title {
				isDuplicate = true
				break
			}
		}

		if !isDuplicate {
			items = append(items, finding)
		}
	}

	return items, nil
}

func html2text(html string) string {
	// Implement html to text conversion if needed
	return html // Placeholder function, needs implementation
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

func stringToUint64(s string) (uint64, error) {
	// Parse the string as a base 10 unsigned integer (uint64)
	value, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}
