package webhook_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
	"github.com/openebl/openebl/pkg/bu_server/webhook"
	mock_storage "github.com/openebl/openebl/test/mock/bu_server/storage"
)

const endpoint = "/notify"

func (s *WebhookControllerTestSuite) TestWebhookEventProcessor() {
	s.mux.HandleFunc(endpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	getRaw := func(t any) []byte {
		raw, _ := json.Marshal(t)
		return raw
	}

	url, err := url.JoinPath(s.server.URL, endpoint)
	s.Require().NoError(err)
	event := model.WebhookEvent{
		ID:        "bl_1",
		Url:       url,
		Type:      "bl.accomplished",
		CreatedAt: 12345,
	}
	msgsOnDB := []storage.OutboxMsg{
		{
			RecID: 1,
			Key:   "hash_value",
			Msg:   getRaw(event),
		},
	}

	rtx1 := mock_storage.NewMockTx(s.ctrl)
	tx := mock_storage.NewMockTx(s.ctrl)
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any()).Return(rtx1, s.ctx, nil),
		s.storage.EXPECT().GetWebhookEvent(gomock.Any(), rtx1, 10).Return(msgsOnDB, nil),
		rtx1.EXPECT().Rollback(gomock.Any()).Return(nil),

		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(tx, s.ctx, nil),
		s.storage.EXPECT().DeleteWebhookEvent(gomock.Any(), tx, gomock.Eq([]int64{1})).Return(nil),
		tx.EXPECT().Commit(gomock.Any()).Return(nil),
		tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	rtx2 := mock_storage.NewMockTx(s.ctrl)
	s.storage.EXPECT().CreateTx(gomock.Any()).Return(rtx2, s.ctx, nil).AnyTimes()
	s.storage.EXPECT().GetWebhookEvent(gomock.Any(), rtx2, 10).Return(nil, nil).AnyTimes()
	rtx2.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := webhook.Config{CheckInterval: 1, BatchSize: 10, Timeout: 5, MaxRetry: 3}
	proc, err := webhook.NewProcessorWithConfig(cfg, webhook.WithStorage(s.storage))
	s.Require().NoError(err)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		proc.Run(ctx)
	}()

	time.Sleep(2 * time.Second)
	cancel()

	wg.Wait()
}

func (s *WebhookControllerTestSuite) TestWebhookEventProcessor_ReturnNon200() {
	s.mux.HandleFunc(endpoint, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	getRaw := func(t any) []byte {
		raw, _ := json.Marshal(t)
		return raw
	}

	url, err := url.JoinPath(s.server.URL, endpoint)
	s.Require().NoError(err)
	event := model.WebhookEvent{
		ID:        "bl_1",
		Url:       url,
		Type:      "bl.accomplished",
		CreatedAt: 12345,
	}
	msgsOnDB := []storage.OutboxMsg{
		{
			RecID: 1,
			Key:   "hash_value",
			Msg:   getRaw(event),
		},
	}

	rtx1 := mock_storage.NewMockTx(s.ctrl)
	tx := mock_storage.NewMockTx(s.ctrl)
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any()).Return(rtx1, s.ctx, nil),
		s.storage.EXPECT().GetWebhookEvent(gomock.Any(), rtx1, 10).Return(msgsOnDB, nil),
		rtx1.EXPECT().Rollback(gomock.Any()).Return(nil),

		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(tx, s.ctx, nil),
		s.storage.EXPECT().DeleteWebhookEvent(gomock.Any(), tx, gomock.Eq([]int64{1})).Return(nil),
		tx.EXPECT().Commit(gomock.Any()).Return(nil),
		tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	rtx2 := mock_storage.NewMockTx(s.ctrl)
	s.storage.EXPECT().CreateTx(gomock.Any()).Return(rtx2, s.ctx, nil).AnyTimes()
	s.storage.EXPECT().GetWebhookEvent(gomock.Any(), rtx2, 10).Return(nil, nil).AnyTimes()
	rtx2.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := webhook.Config{CheckInterval: 1, BatchSize: 10, Timeout: 5, MaxRetry: 3}
	proc, err := webhook.NewProcessorWithConfig(cfg, webhook.WithStorage(s.storage))
	s.Require().NoError(err)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		proc.Run(ctx)
	}()

	time.Sleep(2 * time.Second)
	cancel()

	wg.Wait()
}

func (s *WebhookControllerTestSuite) TestWebhookEventProcessor_ServerUnreachable() {
	s.server.Close() // close the server to make it unreachable

	getRaw := func(t any) []byte {
		raw, _ := json.Marshal(t)
		return raw
	}

	url, err := url.JoinPath(s.server.URL, endpoint)
	s.Require().NoError(err)
	event := model.WebhookEvent{
		ID:        "bl_1",
		Url:       url,
		Type:      "bl.accomplished",
		CreatedAt: 12345,
	}
	msgsOnDB := []storage.OutboxMsg{
		{
			RecID: 1,
			Key:   "hash_value",
			Msg:   getRaw(event),
		},
	}

	rtx1 := mock_storage.NewMockTx(s.ctrl)
	tx := mock_storage.NewMockTx(s.ctrl)
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any()).Return(rtx1, s.ctx, nil),
		s.storage.EXPECT().GetWebhookEvent(gomock.Any(), rtx1, 10).Return(msgsOnDB, nil),
		rtx1.EXPECT().Rollback(gomock.Any()).Return(nil),

		s.storage.EXPECT().CreateTx(gomock.Any(), gomock.Len(2)).Return(tx, s.ctx, nil),
		s.storage.EXPECT().DeleteWebhookEvent(gomock.Any(), tx, gomock.Eq([]int64{1})).Return(nil),
		tx.EXPECT().Commit(gomock.Any()).Return(nil),
		tx.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	rtx2 := mock_storage.NewMockTx(s.ctrl)
	s.storage.EXPECT().CreateTx(gomock.Any()).Return(rtx2, s.ctx, nil).AnyTimes()
	s.storage.EXPECT().GetWebhookEvent(gomock.Any(), rtx2, 10).Return(nil, nil).AnyTimes()
	rtx2.EXPECT().Rollback(gomock.Any()).Return(nil).AnyTimes()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := webhook.Config{CheckInterval: 1, BatchSize: 10, Timeout: 5, MaxRetry: 3}
	proc, err := webhook.NewProcessorWithConfig(cfg, webhook.WithStorage(s.storage))
	s.Require().NoError(err)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		proc.Run(ctx)
	}()

	time.Sleep(2 * time.Second)
	cancel()

	wg.Wait()
}

func (s *WebhookControllerTestSuite) TestWebhookEventProcessor_ContextCancelled() {
	s.mux.HandleFunc(endpoint, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusOK)
	})

	getRaw := func(t any) []byte {
		raw, _ := json.Marshal(t)
		return raw
	}

	url, err := url.JoinPath(s.server.URL, endpoint)
	s.Require().NoError(err)
	event := model.WebhookEvent{
		ID:        "bl_1",
		Url:       url,
		Type:      "bl.accomplished",
		CreatedAt: 12345,
	}
	msgsOnDB := []storage.OutboxMsg{
		{
			RecID: 1,
			Key:   "hash_value",
			Msg:   getRaw(event),
		},
	}

	rtx1 := mock_storage.NewMockTx(s.ctrl)
	gomock.InOrder(
		s.storage.EXPECT().CreateTx(gomock.Any()).Return(rtx1, s.ctx, nil),
		s.storage.EXPECT().GetWebhookEvent(gomock.Any(), rtx1, 10).Return(msgsOnDB, nil),
		rtx1.EXPECT().Rollback(gomock.Any()).Return(nil),
	)

	ctx, cancel := context.WithCancel(context.Background())
	cfg := webhook.Config{CheckInterval: 1, BatchSize: 10, Timeout: 5, MaxRetry: 3}
	proc, err := webhook.NewProcessorWithConfig(cfg, webhook.WithStorage(s.storage))
	s.Require().NoError(err)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		proc.Run(ctx)
	}()

	time.Sleep(2 * time.Second)
	cancel()

	wg.Wait()
}
