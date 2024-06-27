package sonarqube

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	// "time"
	models "vulnerability-management/internal/pkg/models/findings"

	"github.com/k3a/html2text"
)

type SonarQubeClient struct {
	SonarAPIURL    string
	DefaultHeaders map[string]string
	Session        *http.Client
}

type Test struct {
	BranchTag  string
	Engagement Engagement
}

type Engagement struct {
	Product Product
}

type Product struct {
	Name string
}

// type Finding struct {
// 	Title            string
// 	Cwe              string
// 	Description      string
// 	Test             Test
// 	Severity         string
// 	References       string
// 	FilePath         string
// 	Line             int
// 	Active           bool
// 	Verified         bool
// 	FalsePositive    bool
// 	Duplicate        bool
// 	OutOfScope       bool
// 	Mitigated        *string
// 	Mitigation       string
// 	Impact           string
// 	StaticFinding    bool
// 	SonarqubeIssue   *SonarqubeIssue
// 	UniqueIdFromTool string
// }

type SonarqubeIssue struct {
	Key    string
	Status string
	Type   string
}

type TextRange struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartOffset int `json:"startOffset"`
	EndOffset   int `json:"endOffset"`
}

type Impact struct {
	SoftwareQuality string `json:"softwareQuality"`
	Severity        string `json:"severity"`
}

type Issue struct {
	Key       string        `json:"key"`
	Rule      string        `json:"rule"`
	Severity  string        `json:"severity"`
	Component string        `json:"component"`
	Project   string        `json:"project"`
	Line      uint64        `json:"line"`
	Hash      string        `json:"hash"`
	TextRange TextRange     `json:"textRange"`
	Flows     []interface{} `json:"flows"`
	Status    string        `json:"status"`
	Message   string        `json:"message"`
	Effort    string        `json:"effort"`
	Debt      string        `json:"debt"`
	Author    string        `json:"author"`
	Tags      []string      `json:"tags"`
	// CreationDate               time.Time     `json:"creationDate"`
	// UpdateDate                 time.Time     `json:"updateDate"`
	Type                       string        `json:"type"`
	Scope                      string        `json:"scope"`
	QuickFixAvailable          bool          `json:"quickFixAvailable"`
	MessageFormattings         []interface{} `json:"messageFormattings"`
	CodeVariants               []interface{} `json:"codeVariants"`
	CleanCodeAttribute         string        `json:"cleanCodeAttribute"`
	CleanCodeAttributeCategory string        `json:"cleanCodeAttributeCategory"`
	Impacts                    []Impact      `json:"impacts"`
	IssueStatus                string        `json:"issueStatus"`
}

type Hotspot struct {
	Key                      string    `json:"key"`
	Component                string    `json:"component"`
	Project                  string    `json:"project"`
	SecurityCategory         string    `json:"securityCategory"`
	VulnerabilityProbability string    `json:"vulnerabilityProbability"`
	Status                   string    `json:"status"`
	Line                     uint64    `json:"line"`
	Message                  string    `json:"message"`
	Author                   string    `json:"author"`
	CreationDate             string    `json:"creationDate"`
	UpdateDate               string    `json:"updateDate"`
	TextRange                TextRange `json:"textRange"`
	Flows                    []string  `json:"flows"` // Adjust the type based on the actual structure
	RuleKey                  string    `json:"ruleKey"`
	MessageFormattings       []string  `json:"messageFormattings"` // Adjust the type based on the actual structure
}

// / Function to import hotspots from SonarQube
func (c *SonarQubeClient) ImportHotspots(projectKey string) ([]models.Finding, error) {
	var items []models.Finding

	// Determine the component based on configuration or find it by project name
	var err error

	// Fetch hotspots for the component
	hotspots, err := c.FindHotspots(projectKey, "")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch hotspots: %v", err)
	}

	log.Printf("Found %d hotspots for project %s", len(hotspots), projectKey)

	// Remove /api from SonarQube URL to get base URL
	// sonarURL := strings.TrimSuffix(c.SonarAPIURL, "/api")

	// Iterate over hotspots and create Finding objects
	for _, hotspot := range hotspots {
		// status := hotspot.Status

		// // Skip reviewed hotspots
		// if client.isReviewed(status) {
		// 	continue
		// }

		// Determine severity based on vulnerabilityProbability
		var severity uint64
		switch hotspot.VulnerabilityProbability {
		case "CRITICAL":
			severity = 5
		case "HIGH":
			severity = 4
		case "MEDIUM":
			severity = 3
		case "LOW":
			severity = 2
		default:
			severity = 1
		}

		title := hotspot.Message
		if len(title) > 511 {
			title = title[:507] + "..."
		}

		// Prepare references including SonarQube permalink and rule references
		// var references string
		// sonarqubePermalink := fmt.Sprintf("[Hotspot permalink](%s/security_hotspots?id=%s&hotspots=%s) \n", sonarURL, hotspot.Project, hotspot.Key)
		// references = sonarqubePermalink + client.getReferences(hotspot.RuleKey)

		// Fetch additional rule details
		// rule, err := client.getHotspotRule(hotspot.Key)
		// if err != nil {
		// 	return nil, fmt.Errorf("failed to fetch hotspot rule details: %v", err)
		// }

		// Clean rule description and CWE
		description := ""
		// description := c.cleanRuleDescriptionHTML(rule.VulnerabilityDescription)
		var cwe uint64 = 0
		// cwe := c.cleanCWE(rule.FixRecommendations)

		// Update or create Sonarqube_Issue and associate with Finding
		// sonarqubeIssue, _ := SonarqubeIssue.objects.updateOrCreate(
		// 	Key: hotspot.Key,
		// 	Status: status,
		// 	Type: "SECURITY_HOTSPOT",
		// )

		// Only assign the SonarQube_issue to the first finding related
		// to the issue
		// if Finding.objects.filter(
		// 	SonarqubeIssue: sonarqubeIssue,
		// ).exists() {
		// 	sonarqubeIssue = nil
		// }

		// Create Finding object and append to items
		find := models.Finding{
			Title:           title,
			CWE:             cwe,
			RiskDescription: description,
			// TestID:          testID,
			Severity: severity,
			// References:         references,
			FilePath: hotspot.Component,
			Line:     hotspot.Line,
			Active:   true,
			// Verified:         c.isConfirmed(status),
			Duplicate:        false,
			StaticFinding:    true,
			UniqueIDFromTool: fmt.Sprintf("hotspot:%s", hotspot.Key),
		}
		items = append(items, find)
	}

	return items, nil
}

func (c *SonarQubeClient) ImportIssues(projectKey string) ([]models.Finding, error) {
	var items []models.Finding

	// client, config := c.prepareClient(test)

	issues, err := c.FindIssues(projectKey, "BUG", "")
	if err != nil {
		fmt.Printf("Error finding issues: %v", err)
		return nil, err
	}

	fmt.Printf("Found %d issues for component %s", len(issues), projectKey)

	// sonarUrl := strings.TrimSuffix(c.SonarAPIURL, "/api")

	for _, issue := range issues {
		status := issue.Status

		if c.isClosed(status) {
			continue
		}

		message := issue.Message
		title := message
		if len(message) > 511 {
			title = message[:507] + "..."
		}

		componentKey := issue.Component
		line := issue.Line
		// ruleId := issue.Rule
		// rule, err := c.getRule(ruleId)
		// if err != nil {
		// 	log.Printf("Error getting rule: %v", err)
		// 	continue
		// }

		severity := c.convertSonarSeverity(issue.Severity)
		// sonarqubePermalink := fmt.Sprintf("[Issue permalink](%s/project/issues?issues=%s&open=%s&resolved=%s&id=%s) \n", sonarUrl, issue.Key, issue.Key, issue.Status, issue.Project)

		var description, references string
		var cwe uint64
		// if htmlDesc, ok := rule["htmlDesc"].(string); ok {
		// 	description = c.cleanRuleDescriptionHtml(htmlDesc)
		// 	cwe = c.cleanCwe(htmlDesc)
		// 	references = sonarqubePermalink + c.getReferences(htmlDesc)
		// } else {
		// 	description = ""
		// 	cwe = nil
		// 	references = sonarqubePermalink
		// }

		find := models.Finding{
			Title:            title,
			CWE:              cwe,
			RiskDescription:  description,
			Severity:         severity,
			Reference:        references,
			FilePath:         componentKey,
			Line:             line,
			Duplicate:        false,
			Mitigation:       "nil",
			Impact:           "No impact provided",
			StaticFinding:    true,
			UniqueIDFromTool: issue.Key,
		}
		items = append(items, find)
	}

	return items, nil
}

func (c *SonarQubeClient) FindHotspots(projectKey string, branch string) ([]Hotspot, error) {
	page := 1
	maxPage := 100
	hotspots := []Hotspot{}

	for page <= maxPage {
		requestFilter := url.Values{}
		requestFilter.Add("projectKey", projectKey)
		requestFilter.Add("p", fmt.Sprintf("%d", page))

		if branch != "" {
			requestFilter.Add("branch", branch)
		}

		requestUrl := fmt.Sprintf("%s/hotspots/search?%s", c.SonarAPIURL, requestFilter.Encode())
		req, err := http.NewRequest("GET", requestUrl, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}

		for key, value := range c.DefaultHeaders {
			req.Header.Set(key, value)
		}

		resp, err := c.Session.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to execute request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("unable to find the hotspots for project %s due to %d - %s",
				projectKey, resp.StatusCode, string(body))
		}

		var result struct {
			Hotspots []Hotspot `json:"hotspots"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("failed to decode response: %v", err)
		}

		if len(result.Hotspots) == 0 {
			break
		}

		hotspots = append(hotspots, result.Hotspots...)
		page++
	}
	fmt.Println(hotspots)
	fmt.Println(len(hotspots))

	return hotspots, nil
}

func (c *SonarQubeClient) FindIssues(componentKey string, types string, branch string) ([]Issue, error) {

	page := 1
	maxPage := 100
	issues := []Issue{}

	for page <= maxPage {
		requestFilter := url.Values{}
		requestFilter.Add("componentKeys", componentKey)
		requestFilter.Add("types", types)
		requestFilter.Add("p", fmt.Sprintf("%d", page))

		if branch != "" {
			requestFilter.Add("branch", branch)
		}

		requestUrl := fmt.Sprintf("%s/issues/search?%s", c.SonarAPIURL, requestFilter.Encode())
		req, err := http.NewRequest("GET", requestUrl, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}

		for key, value := range c.DefaultHeaders {
			req.Header.Set(key, value)
		}

		resp, err := c.Session.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to execute request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("unable to find the issues for component %s due to %d - %s",
				componentKey, resp.StatusCode, string(body))
		}

		var result struct {
			Issues []Issue `json:"issues"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("failed to decode response: %v", err)
		}

		if len(result.Issues) == 0 {
			break
		}

		issues = append(issues, result.Issues...)
		page++
	}
	fmt.Println(issues)
	fmt.Println(len(issues))
	return issues, nil
}

func (c *SonarQubeClient) isClosed(state string) bool {
	closedStates := []string{
		"resolved",
		"falsepositive",
		"wontfix",
		"closed",
		"dismissed",
		"rejected",
	}

	state = strings.ToLower(state)
	for _, closedState := range closedStates {
		if state == closedState {
			return true
		}
	}
	return false
}

func (c *SonarQubeClient) convertSonarSeverity(sonarSeverity string) uint64 {
	sev := strings.ToLower(sonarSeverity)
	switch sev {
	case "blocker":
		return 5
	case "critical":
		return 4
	case "major":
		return 3
	case "minor":
		return 2
	default:
		return 1
	}
}

func (c *SonarQubeClient) cleanRuleDescriptionHtml(rawHtml string) string {
	// Regular expression to match the beginning part of the HTML
	re := regexp.MustCompile(`^(.*?)(?:(<h2>See</h2>)|(<b>References</b>))`)
	match := re.FindStringSubmatch(rawHtml)

	if len(match) > 0 {
		rawHtml = match[1]
	}

	// Replace <h2> tags with <b> for compatibility with html2text
	rawHtml = strings.ReplaceAll(rawHtml, "<h2>", "<b>")
	rawHtml = strings.ReplaceAll(rawHtml, "</h2>", "</b>")

	// Convert HTML to plain text
	text := html2text.HTML2Text(rawHtml)

	return text
}

func (c *SonarQubeClient) getRule(ruleId string) (string, error) {
	requestFilter := map[string]string{"key": ruleId}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/rules/show", c.SonarAPIURL), nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range c.DefaultHeaders {
		req.Header.Set(key, value)
	}

	q := req.URL.Query()
	for key, value := range requestFilter {
		q.Add(key, value)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := c.Session.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Unable to get the rule %s due to %d - %s", ruleId, resp.StatusCode, resp.Status)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}

	return data["rule"].(string), nil
}

func (c *SonarQubeClient) isConfirmed(state string) bool {
	lowerState := strings.ToLower(state)
	return lowerState == "confirmed" || lowerState == "accepted" || lowerState == "detected"
}
