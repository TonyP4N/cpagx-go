package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestVersionProxyTaskFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cpag/generate":
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"task_id":"synthetic"}`))
		case "/cpag/status/batch":
			if r.URL.Query().Get("task_ids") != "synthetic&a=b" {
				t.Errorf("query changed: %s", r.URL.RawQuery)
			}
			w.Write([]byte(`{"synthetic":{"status":"SUCCESS"}}`))
		case "/cpag/result/synthetic":
			w.Write([]byte(`{"status":"success"}`))
		case "/cpag/download/synthetic/graph.json":
			w.Header().Set("Content-Disposition", `attachment; filename="graph.json"`)
			w.Write([]byte("graph"))
		case "/cpag/download/missing/graph.json":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"detail":"missing"}`))
		case "/cpag/tasks":
			w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected upstream path: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	t.Setenv("PYTHON_V2_SERVICE_URL", upstream.URL)
	proxy := NewVersionProxy(&Config{Versions: map[string]VersionInfo{"v2": {Enabled: true}}})
	r := gin.New()
	r.Any("/api/v2/*path", proxy.ProxyToVersion("v2"))
	r.GET("/api/tasks/download/:task_id/:filename", proxy.DownloadFile())
	r.GET("/api/tasks/status/batch", proxy.GetBatchTaskStatus())
	r.GET("/api/tasks/list", proxy.GetTaskList())
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{"POST", "/api/v2/cpag/generate", 202, `{"task_id":"synthetic"}`},
		{"GET", "/api/v2/cpag/result/synthetic", 200, `{"status":"success"}`},
		{"GET", "/api/tasks/status/batch?version=v2&task_ids=synthetic%26a%3Db", 200, `{"synthetic":{"status":"SUCCESS"}}`},
		{"GET", "/api/tasks/download/synthetic/graph.json?version=v2", 200, "graph"},
		{"GET", "/api/tasks/download/missing/graph.json?version=v2", 404, `{"detail":"missing"}`},
		{"GET", "/api/tasks/list", 200, "[]"},
	} {
		w := httptest.NewRecorder()
		ctx, cancel := context.WithCancel(context.Background())
		r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil).WithContext(ctx))
		cancel()
		if w.Code != tc.status || w.Body.String() != tc.body {
			t.Errorf("%s: got %d %s", tc.path, w.Code, w.Body.String())
		}
		if strings.Contains(tc.path, "/api/v2/") && w.Header().Get("X-Cpag-Version") != "v2" {
			t.Error("incorrect version header")
		}
		if tc.body == "graph" && w.Header().Get("Content-Disposition") == "" {
			t.Error("lost download filename")
		}
	}
}

func TestUnhealthyTaskListAndSwitch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte(`{"detail":"offline"}`))
	}))
	defer upstream.Close()
	t.Setenv("PYTHON_V1_SERVICE_URL", upstream.URL)
	p := NewVersionProxy(&Config{Versions: map[string]VersionInfo{"v1": {Enabled: true}}})
	r := gin.New()
	r.GET("/list", p.GetTaskList())
	r.POST("/switch", p.SwitchVersion())
	for _, tc := range []struct{ method, path, body string }{{"GET", "/list", ""}, {"POST", "/switch", `{"version":"v1"}`}} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != 503 {
			t.Errorf("%s hid upstream failure: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
}
