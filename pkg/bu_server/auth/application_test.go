package auth_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	mock_auth "github.com/openebl/openebl/test/mock/bu_server/auth"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
	"github.com/stretchr/testify/suite"
)

type ApplicationManagerTestSuite struct {
	suite.Suite
	ctx     context.Context
	ctrl    *gomock.Controller
	storage *mock_auth.MockApplicationStorage
	tx      *mock_storage.MockTx
	mgr     auth.ApplicationManager
}

func TestApplicationManager(t *testing.T) {
	suite.Run(t, &ApplicationManagerTestSuite{})
}

func (s *ApplicationManagerTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.ctrl = gomock.NewController(s.T())
	s.storage = mock_auth.NewMockApplicationStorage(s.ctrl)
	s.tx = mock_storage.NewMockTx(s.ctrl)
	s.mgr = auth.NewApplicationManager(s.storage)
}

func (s *ApplicationManagerTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *ApplicationManagerTestSuite) TestCreateApplication() {
	// Prepare test data
	req := auth.CreateApplicationRequest{
		RequestUser: auth.RequestUser{
			User: "testuser",
		},
		Name:         "Test Application",
		CompanyName:  "Test Company",
		Addresses:    []string{"Address 1", "Address 2"},
		Emails:       []string{"email1@example.com", "email2@example.com"},
		PhoneNumbers: []string{"1234567890", "0987654321"},
	}

	var storedApp auth.Application

	// Set expectations
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Any()).Return(s.tx, nil),
		s.storage.EXPECT().StoreApplication(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, app auth.Application) error {
				storedApp = app
				return nil
			},
		).Return(nil),
		s.tx.EXPECT().Commit(gomock.Eq(s.ctx)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	// Call the function under test
	app, err := s.mgr.CreateApplication(s.ctx, 1234567890, req)

	// Assert the result
	s.NoError(err)
	s.Equal(storedApp, app)
	s.NotEmpty(app.ID)
	s.EqualValues(1, app.Version)
	s.Equal(auth.ApplicationStatusInactive, app.Status)
	s.Equal("Test Application", app.Name)
	s.Equal("Test Company", app.CompanyName)
	s.Equal([]string{"Address 1", "Address 2"}, app.Addresses)
	s.Equal([]string{"email1@example.com", "email2@example.com"}, app.Emails)
	s.Equal([]string{"1234567890", "0987654321"}, app.PhoneNumbers)
}

func (s *ApplicationManagerTestSuite) TestUpdateApplication() {
	// Prepare the old application.
	oldApp := auth.Application{
		ID:           "test_application_id",
		Version:      1,
		Status:       auth.ApplicationStatusInactive,
		CreatedAt:    1234567890,
		CreatedBy:    "testuser",
		UpdatedAt:    1234567890,
		Name:         "Old Application",
		CompanyName:  "Old Company",
		Addresses:    []string{"Old Address 1", "Old Address 2"},
		Emails:       []string{"old_email1@example.com", "old_email2@example.com"},
		PhoneNumbers: []string{"1234567890", "0987654321"},
	}

	// Prepare test data
	req := auth.UpdateApplicationRequest{
		CreateApplicationRequest: auth.CreateApplicationRequest{
			RequestUser: auth.RequestUser{
				User: "testuser",
			},
			Name:         "Updated Application",
			CompanyName:  "Updated Company",
			Addresses:    []string{"Updated Address 1", "Updated Address 2"},
			Emails:       []string{"updated_email1@example.com", "updated_email2@example.com"},
			PhoneNumbers: []string{"9876543210", "0123456789"},
		},
		ID: "test_application_id",
	}

	var updatedApp auth.Application

	// Set expectations
	// Prepare the expected ListApplicationRequest
	expectedReq := auth.ListApplicationRequest{
		Limit: 1,
		IDs:   []string{"test_application_id"},
	}
	listAppResult := auth.ListApplicationResult{
		Total:        1,
		Applications: []auth.Application{oldApp},
	}
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Eq(s.ctx), gomock.Any()).Return(s.tx, nil),
		s.storage.EXPECT().ListApplication(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Eq(expectedReq)).Return(listAppResult, nil),
		s.storage.EXPECT().StoreApplication(gomock.Eq(s.ctx), gomock.Eq(s.tx), gomock.Any()).DoAndReturn(
			func(ctx context.Context, tx storage.Tx, app auth.Application) error {
				updatedApp = app
				return nil
			},
		).Return(nil),
		s.tx.EXPECT().Commit(gomock.Eq(s.ctx)).Return(nil),
		s.tx.EXPECT().Rollback(gomock.Eq(s.ctx)).Return(nil),
	)

	// Call the function under test
	app, err := s.mgr.UpdateApplication(s.ctx, 1234567890, req)

	// Assert the result
	s.NoError(err)
	s.Equal(updatedApp, app)
	s.Equal("test_application_id", app.ID)
	s.EqualValues(2, app.Version)
	s.Equal(auth.ApplicationStatusInactive, app.Status)
	s.Equal("Updated Application", app.Name)
	s.Equal("Updated Company", app.CompanyName)
	s.Equal([]string{"Updated Address 1", "Updated Address 2"}, app.Addresses)
	s.Equal([]string{"updated_email1@example.com", "updated_email2@example.com"}, app.Emails)
	s.Equal([]string{"9876543210", "0123456789"}, app.PhoneNumbers)
}
