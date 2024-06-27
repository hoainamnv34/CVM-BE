package persistence

import (
	db "vulnerability-management/internal/pkg/db"
	models "vulnerability-management/internal/pkg/models/findings"
)

type FindingRepository struct{}

var FindingRepo *FindingRepository = &FindingRepository{}

func (r *FindingRepository) Get(id string) (*models.Finding, error) {
	finding := models.Finding{}

	err := db.DB.Model(&models.Finding{}).Where("id = ?", id).First(&finding).Error
	if err != nil {
		return nil, err
	}

	return &finding, err
}

func (r *FindingRepository) Query(where interface{}, offset int, limit int) (*[]models.Finding, int, error) {
	findings := []models.Finding{}

	count := 0

	query := db.DB.Model(&models.Finding{}).Where(where)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("id DESC").Find(&findings).Error
	if err != nil {
		return nil, 0, err
	}

	return &findings, count, err
}

func (r *FindingRepository) Count(where interface{}) (int, error) {
	count := 0

	err := db.DB.Model(&models.Finding{}).Where(where).Count(&count).Error

	return count, err
}

func (r *FindingRepository) Add(finding *models.Finding) (*models.Finding, error) {
	err := db.DB.Model(&models.Finding{}).Create(finding).Error

	return finding, err
}

func (r *FindingRepository) Update(finding *models.Finding) error {
	err := db.DB.Model(&models.Finding{}).Save(finding).Error

	return err
}

func (r *FindingRepository) Delete(finding *models.Finding) error {
	err := db.DB.Model(&models.Finding{}).Delete(finding).Error

	return err
}

func (r *FindingRepository) QueryByProjectGroupID(projectGroupID uint64, offset int, limit int) (*[]models.Finding, int, error) {
	findings := []models.Finding{}

	count := 0

	// query := db.DB.Table("findings").
	// 	Select("findings.*").
	// 	Joins("JOIN tests ON findings.test_id = tests.id").
	// 	Joins("JOIN pipeline_runs ON tests.pipeline_run_id = pipeline_runs.id").
	// 	Joins("JOIN cicd_pipelines ON pipeline_runs.cicd_pipeline_id = cicd_pipelines.id").
	// 	Joins("JOIN projects ON cicd_pipelines.project_id = projects.id").
	// 	Joins("JOIN project_groups ON projects.project_group_id = project_groups.id").
	// 	Where("project_groups.id = ?", projectGroupID)

	query := db.DB.Table("findings").
		Select("findings.*").
		Joins("JOIN projects ON findings.project_id = projects.id").
		Joins("JOIN project_groups ON projects.project_group_id = project_groups.id").
		Where("project_groups.id = ?", projectGroupID)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("findings.id DESC").Find(&findings).Error
	if err != nil {
		return nil, 0, err
	}

	return &findings, count, err
}

func (r *FindingRepository) QueryByProjectID(projectID uint64, offset int, limit int) (*[]models.Finding, int, error) {
	findings := []models.Finding{}

	count := 0

	query := db.DB.Table("findings").
		Select("findings.*").
		Where("findings.project_id= ?", projectID)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("findings.id DESC").Find(&findings).Error
	if err != nil {
		return nil, 0, err
	}

	return &findings, count, err
}

func (r *FindingRepository) QueryByPipelineRunID(PipelineRunID uint64, offset int, limit int) (*[]models.Finding, int, error) {
	findings := []models.Finding{}

	count := 0

	query := db.DB.Table("findings").
		Select("findings.*").
		Joins("JOIN finding_tests ON findings.id = finding_tests.finding_id").
		Joins("JOIN tests ON finding_tests.test_id = tests.id").
		Joins("JOIN pipeline_runs ON tests.pipeline_run_id = pipeline_runs.id").
		Where("pipeline_runs.id = ?", PipelineRunID)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("findings.id DESC").Find(&findings).Error
	if err != nil {
		return nil, 0, err
	}

	return &findings, count, err
}

func (r *FindingRepository) QueryByTestID(TestID uint64, offset int, limit int) (*[]models.Finding, int, error) {
	findings := []models.Finding{}

	count := 0

	query := db.DB.Table("findings").
		Select("findings.*").
		Joins("JOIN finding_tests ON findings.id = finding_tests.finding_id").
		Joins("JOIN tests ON finding_tests.test_id = tests.id").
		Where("tests.id = ?", TestID)

	err := query.Count(&count).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(offset).Limit(limit).Order("findings.id DESC").Find(&findings).Error
	if err != nil {
		return nil, 0, err
	}

	return &findings, count, err
}

func (r *FindingRepository) CountByProjectGroupID(projectGroupID uint64) (int, error) {
	count := 0

	err := db.DB.Table("findings").
		Select("findings.*").
		Joins("JOIN projects ON findings.project_id = projects.id").
		Joins("JOIN project_groups ON projects.project_group_id = project_groups.id").
		Where("project_groups.id = ?", projectGroupID).
		Count(&count).Error

	return count, err
}

func (r *FindingRepository) CountByProjectID(projectID uint64) (int, error) {
	count := 0

	err := db.DB.Table("findings").
		Select("findings.*").
		Where("findings.project_id= ?", projectID).
		Count(&count).Error

	return count, err
}

func (r *FindingRepository) CountByPipelineRunID(pipelineRunID uint64) (int, error) {
	count := 0

	err := db.DB.Table("findings").
		Select("findings.*").
		Joins("JOIN finding_tests ON findings.id = finding_tests.finding_id").
		Joins("JOIN tests ON finding_tests.test_id = tests.id").
		Joins("JOIN pipeline_runs ON tests.pipeline_run_id = pipeline_runs.id").
		Where("pipeline_runs.id = ?", pipelineRunID).
		Count(&count).Error

	return count, err
}

func (r *FindingRepository) CountByTestID(testID uint64) (int, error) {
	count := 0

	err := db.DB.Table("findings").
		Select("findings.*").
		Joins("JOIN finding_tests ON findings.id = finding_tests.finding_id").
		Joins("JOIN tests ON finding_tests.test_id = tests.id").
		Where("tests.id = ?", testID).
		Count(&count).Error

	return count, err
}

func (r *FindingRepository) CountByPipelineRunIDAndSeverity(pipelineRunID uint64, severity uint64) (int, error) {
	count := 0

	err := db.DB.Table("findings").
		Select("findings.*").
		Joins("JOIN finding_tests ON findings.id = finding_tests.finding_id").
		Joins("JOIN tests ON finding_tests.test_id = tests.id").
		Joins("JOIN pipeline_runs ON tests.pipeline_run_id = pipeline_runs.id").
		Where("pipeline_runs.id = ?", pipelineRunID).
		Where("findings.severity = ?", severity).
		Count(&count).Error

	return count, err
}
