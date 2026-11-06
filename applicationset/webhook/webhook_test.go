package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-playground/webhooks/v6/gogs"
	gogsclient "github.com/gogits/go-gogs-client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/argoproj/argo-cd/v3/applicationset/generators"
	"github.com/argoproj/argo-cd/v3/applicationset/services/scm_provider"
	"github.com/argoproj/argo-cd/v3/common"
	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	argosettings "github.com/argoproj/argo-cd/v3/util/settings"
)

type generatorMock struct {
	mock.Mock
}

func (g *generatorMock) GetTemplate(_ *v1alpha1.ApplicationSetGenerator) *v1alpha1.ApplicationSetTemplate {
	return &v1alpha1.ApplicationSetTemplate{}
}

func (g *generatorMock) GenerateParams(_ *v1alpha1.ApplicationSetGenerator, _ *v1alpha1.ApplicationSet, _ client.Client) ([]map[string]any, error) {
	return []map[string]any{}, nil
}

func (g *generatorMock) GetRequeueAfter(_ *v1alpha1.ApplicationSetGenerator) time.Duration {
	d, _ := time.ParseDuration("10s")
	return d
}

func TestWebhookHandler(t *testing.T) {
	t.Parallel()
	tt := []struct {
		desc               string
		headerKey          string
		headerValue        string
		headers            map[string]string
		effectedAppSets    []string
		payloadFile        string
		expectedStatusCode int
		expectedRefresh    bool
	}{
		{
			desc:               "WebHook from a GitHub repository via Commit",
			headerKey:          "X-GitHub-Event",
			headerValue:        "push",
			payloadFile:        "github-commit-event.json",
			effectedAppSets:    []string{"git-github", "git-github-ssh", "git-github-alt-ssh", "matrix-git-github", "merge-git-github", "matrix-scm-git-github", "matrix-nested-git-github", "merge-nested-git-github", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook from a GitHub repository via Commit shorthand",
			headerKey:          "X-GitHub-Event",
			headerValue:        "push",
			payloadFile:        "github-commit-event-feature-branch.json",
			effectedAppSets:    []string{"github-shorthand", "matrix-pull-request-github-plugin", "plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook from a GitHub repository via Commit to branch",
			headerKey:          "X-GitHub-Event",
			headerValue:        "push",
			payloadFile:        "github-commit-branch-event.json",
			effectedAppSets:    []string{"git-github", "git-github-ssh", "git-github-alt-ssh", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook from a GitHub ping event",
			headerKey:          "X-GitHub-Event",
			headerValue:        "ping",
			payloadFile:        "github-ping-event.json",
			effectedAppSets:    []string{"git-github", "git-github-ssh", "git-github-alt-ssh", "plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    false,
		},
		{
			desc:               "WebHook from a GitLab repository via Commit",
			headerKey:          "X-Gitlab-Event",
			headerValue:        "Push Hook",
			payloadFile:        "gitlab-event.json",
			effectedAppSets:    []string{"git-gitlab", "git-gitlab-ssh", "git-gitlab-alt-ssh", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook from a System Hook via Commit",
			headerKey:          "X-Gitlab-Event",
			headerValue:        "System Hook",
			payloadFile:        "gitlab-event.json",
			effectedAppSets:    []string{"git-gitlab", "git-gitlab-ssh", "git-gitlab-alt-ssh", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook with an unknown event",
			headerKey:          "X-Random-Event",
			headerValue:        "Push Hook",
			payloadFile:        "gitlab-event.json",
			effectedAppSets:    []string{"git-gitlab", "git-gitlab-ssh", "git-gitlab-alt-ssh", "plugin"},
			expectedStatusCode: http.StatusBadRequest,
			expectedRefresh:    false,
		},
		{
			desc:               "WebHook with an invalid event",
			headerKey:          "X-Random-Event",
			headerValue:        "Push Hook",
			payloadFile:        "invalid-event.json",
			effectedAppSets:    []string{"git-gitlab", "git-gitlab-ssh", "git-gitlab-alt-ssh", "plugin"},
			expectedStatusCode: http.StatusBadRequest,
			expectedRefresh:    false,
		},
		{
			desc:               "WebHook from a Gitea repository via Commit",
			headers:            giteaHeaders("push", "push", "", nil),
			payloadFile:        "gitea-push-event.json",
			effectedAppSets:    []string{"git-gitea", "git-gitea-ssh", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook from a GitHub repository via pull_request opened event",
			headerKey:          "X-GitHub-Event",
			headerValue:        "pull_request",
			payloadFile:        "github-pull-request-opened-event.json",
			effectedAppSets:    []string{"pull-request-github", "matrix-pull-request-github", "matrix-scm-pull-request-github", "merge-pull-request-github", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook from a GitHub repository via pull_request assigned event",
			headerKey:          "X-GitHub-Event",
			headerValue:        "pull_request",
			payloadFile:        "github-pull-request-assigned-event.json",
			effectedAppSets:    []string{"pull-request-github", "matrix-pull-request-github", "matrix-scm-pull-request-github", "merge-pull-request-github", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    false,
		},
		{
			desc:               "WebHook from a GitHub repository via pull_request labeled event",
			headerKey:          "X-GitHub-Event",
			headerValue:        "pull_request",
			payloadFile:        "github-pull-request-labeled-event.json",
			effectedAppSets:    []string{"pull-request-github", "matrix-pull-request-github", "matrix-scm-pull-request-github", "merge-pull-request-github", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook from a Gitea repository via pull_request opened event",
			headers:            giteaHeaders("pull_request", "pull_request", "", nil),
			payloadFile:        "gitea-pull-request-opened-event.json",
			effectedAppSets:    []string{"pull-request-gitea", "pull-request-gitea-case", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook from a Gitea repository via pull_request synchronized event",
			headers:            giteaHeaders("pull_request", "pull_request_sync", "", nil),
			payloadFile:        "gitea-pull-request-synchronized-event.json",
			effectedAppSets:    []string{"pull-request-gitea", "pull-request-gitea-case", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook from a Gitea repository via pull_request assigned event",
			headers:            giteaHeaders("pull_request", "pull_request_assign", "", nil),
			payloadFile:        "gitea-pull-request-assigned-event.json",
			effectedAppSets:    []string{"pull-request-gitea", "pull-request-gitea-case", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    false,
		},
		{
			desc:               "WebHook from a GitLab repository via open merge request event",
			headerKey:          "X-Gitlab-Event",
			headerValue:        "Merge Request Hook",
			payloadFile:        "gitlab-merge-request-open-event.json",
			effectedAppSets:    []string{"pull-request-gitlab", "pull-request-gitlab-path", "pull-request-gitlab-path-case", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook from a GitLab repository via approval merge request event",
			headerKey:          "X-Gitlab-Event",
			headerValue:        "Merge Request Hook",
			payloadFile:        "gitlab-merge-request-approval-event.json",
			effectedAppSets:    []string{"pull-request-gitlab", "pull-request-gitlab-path", "pull-request-gitlab-path-case", "plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    false,
		},
		{
			desc:               "WebHook from a Azure DevOps repository via Commit",
			headerKey:          "X-Vss-Activityid",
			headerValue:        "Push Hook",
			payloadFile:        "azuredevops-push.json",
			effectedAppSets:    []string{"git-azure-devops", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "WebHook from a Azure DevOps repository via pull request event",
			headerKey:          "X-Vss-Activityid",
			headerValue:        "Pull Request Hook",
			payloadFile:        "azuredevops-pull-request.json",
			effectedAppSets:    []string{"pull-request-azure-devops", "plugin", "matrix-pull-request-github-plugin"},
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
	}

	namespace := "test"
	webhookParallelism := 10
	fakeClient := newFakeClient(namespace)
	scheme := runtime.NewScheme()
	err := v1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	err = v1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	for _, test := range tt {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				fakeAppWithGitGenerator("git-github", namespace, "https://github.com/org/repo"),
				fakeAppWithGitGenerator("git-github-copy", namespace, "https://github.com/org/repo-copy"),
				fakeAppWithGitGenerator("git-github-ssh", namespace, "ssh://git@github.com/org/repo"),
				fakeAppWithGitGenerator("git-github-alt-ssh", namespace, "ssh://git@ssh.github.com:443/org/repo"),
				fakeAppWithGitGenerator("git-gitlab", namespace, "https://gitlab.com/group/name"),
				fakeAppWithGitGenerator("git-gitlab-ssh", namespace, "ssh://git@gitlab.com/group/name"),
				fakeAppWithGitGenerator("git-gitlab-alt-ssh", namespace, "ssh://git@altssh.gitlab.com:443/group/name"),
				fakeAppWithGitGenerator("git-azure-devops", namespace, "https://dev.azure.com/fabrikam-fiber-inc/DefaultCollection/_git/Fabrikam-Fiber-Git"),
				fakeAppWithGitGeneratorWithRevision("git-gitea", namespace, "http://gitea/Codertocat/Hello-World", "HEAD"),
				fakeAppWithGitGeneratorWithRevision("git-gitea-ssh", namespace, "ssh://git@gitea:2222/Codertocat/Hello-World.git", "dev"),
				fakeAppWithGitGenerator("git-gitea-other-branch", namespace, "http://gitea/Codertocat/Hello-World"),
				fakeAppWithGitGeneratorWithRevision("github-shorthand", namespace, "https://github.com/org/repo", "env/dev"),
				fakeAppWithGithubPullRequestGenerator("pull-request-github", namespace, "CodErTOcat", "Hello-World"),
				fakeAppWithGitlabPullRequestGenerator("pull-request-gitlab", namespace, "100500"),
				fakeAppWithGitlabPullRequestGenerator("pull-request-gitlab-path", namespace, "group/name"),
				fakeAppWithGitlabPullRequestGenerator("pull-request-gitlab-path-case", namespace, "Group/Name"),
				fakeAppWithGitlabPullRequestGenerator("pull-request-gitlab-path-nomatch", namespace, "group/other"),
				fakeAppWithAzureDevOpsPullRequestGenerator("pull-request-azure-devops", namespace, "DefaultCollection", "Fabrikam"),
				fakeAppWithGiteaPullRequestGenerator("pull-request-gitea", namespace, "Codertocat", "Hello-World", "http://gitea/"),
				fakeAppWithGiteaPullRequestGenerator("pull-request-gitea-case", namespace, "coDErtoCat", "hello-world", "http://GITEA:3000"),
				fakeAppWithGiteaPullRequestGenerator("pull-request-gitea-other-host", namespace, "Codertocat", "Hello-World", "https://gitea.example.com/"),
				fakeAppWithPluginGenerator("plugin", namespace),
				fakeAppWithMatrixAndGitGenerator("matrix-git-github", namespace, "https://github.com/org/repo"),
				fakeAppWithMatrixAndPullRequestGenerator("matrix-pull-request-github", namespace, "Codertocat", "Hello-World"),
				fakeAppWithMatrixAndScmWithGitGenerator("matrix-scm-git-github", namespace, "org"),
				fakeAppWithMatrixAndScmWithPullRequestGenerator("matrix-scm-pull-request-github", namespace, "Codertocat"),
				fakeAppWithMatrixAndNestedGitGenerator("matrix-nested-git-github", namespace, "https://github.com/org/repo"),
				fakeAppWithMatrixAndPullRequestGeneratorWithPluginGenerator("matrix-pull-request-github-plugin", namespace, "coDErtoCat", "HeLLO-WorLD", "plugin-cm"),
				fakeAppWithMergeAndGitGenerator("merge-git-github", namespace, "https://github.com/org/repo"),
				fakeAppWithMergeAndPullRequestGenerator("merge-pull-request-github", namespace, "Codertocat", "Hello-World"),
				fakeAppWithMergeAndNestedGitGenerator("merge-nested-git-github", namespace, "https://github.com/org/repo"),
			).Build()
			set := argosettings.NewSettingsManager(t.Context(), fakeClient, namespace)
			h, err := NewWebhookHandler(webhookParallelism, set, fc, mockGenerators())
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/webhook", http.NoBody)
			if test.headerKey != "" {
				req.Header.Set(test.headerKey, test.headerValue)
			}
			for key, value := range test.headers {
				req.Header.Set(key, value)
			}
			eventJSON, err := os.ReadFile(filepath.Join("testdata", test.payloadFile))
			require.NoError(t, err)
			req.Body = io.NopCloser(bytes.NewReader(eventJSON))
			w := httptest.NewRecorder()

			h.Handler(w, req)
			close(h.queue)
			h.Wait()
			assert.Equal(t, test.expectedStatusCode, w.Code)

			list := &v1alpha1.ApplicationSetList{}
			err = fc.List(t.Context(), list)
			require.NoError(t, err)
			effectedAppSetsAsExpected := make(map[string]bool)
			for _, appSetName := range test.effectedAppSets {
				effectedAppSetsAsExpected[appSetName] = false
			}
			for i := range list.Items {
				gotAppSet := &list.Items[i]
				if _, isEffected := effectedAppSetsAsExpected[gotAppSet.Name]; isEffected {
					expected, got := test.expectedRefresh, gotAppSet.RefreshRequired()
					require.Equalf(t, expected, got, "unexpected RefreshRequired() for appset '%s' expect: %v got: %v", gotAppSet.Name, expected, got)
					effectedAppSetsAsExpected[gotAppSet.Name] = true
				} else {
					assert.False(t, gotAppSet.RefreshRequired())
				}
			}
			for appSetName, checked := range effectedAppSetsAsExpected {
				assert.True(t, checked, "appset %s not found", appSetName)
			}
		})
	}
}

// TestWebhookHandlerGogsSecret covers the signature check of Gitea webhooks, which
// the ApplicationSet webhook verifies with webhook.gogs.secret like the API server.
// A failed signature check is answered like any other parse error.
func TestWebhookHandlerGogsSecret(t *testing.T) {
	t.Parallel()
	namespace := "test"
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	eventJSON, err := os.ReadFile(filepath.Join("testdata", "gitea-pull-request-opened-event.json"))
	require.NoError(t, err)

	tests := []struct {
		desc               string
		giteaSecret        string
		expectedStatusCode int
		expectedError      error
		expectedRefresh    bool
	}{
		{
			desc:               "event signed with webhook.gogs.secret refreshes",
			giteaSecret:        "gogs-secret",
			expectedStatusCode: http.StatusOK,
			expectedRefresh:    true,
		},
		{
			desc:               "event with an invalid signature is rejected",
			giteaSecret:        "wrong-secret",
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      gogs.ErrHMACVerificationFailed,
		},
		{
			desc:               "event signed with webhook.github.secret is rejected",
			giteaSecret:        "github-secret",
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      gogs.ErrHMACVerificationFailed,
		},
		{
			desc:               "event without a signature is rejected",
			giteaSecret:        "",
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      gogs.ErrMissingGogsSignatureHeader,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			kubeClient := newFakeClientWithSettings(namespace, map[string][]byte{
				"webhook.gogs.secret":   []byte("gogs-secret"),
				"webhook.github.secret": []byte("github-secret"),
			})
			fc := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				fakeAppWithGiteaPullRequestGenerator("pull-request-gitea", namespace, "Codertocat", "Hello-World", "http://gitea/"),
			).Build()
			set := argosettings.NewSettingsManager(t.Context(), kubeClient, namespace)
			h, err := NewWebhookHandler(1, set, fc, mockGenerators())
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/webhook", bytes.NewReader(eventJSON))
			for key, value := range giteaHeaders("pull_request", "pull_request", test.giteaSecret, eventJSON) {
				req.Header.Set(key, value)
			}
			w := httptest.NewRecorder()

			h.Handler(w, req)
			close(h.queue)
			h.Wait()
			assert.Equal(t, test.expectedStatusCode, w.Code)
			if test.expectedError != nil {
				assert.Equal(t, "Webhook processing failed: "+test.expectedError.Error(), strings.TrimSpace(w.Body.String()))
			}

			appSet := &v1alpha1.ApplicationSet{}
			require.NoError(t, fc.Get(t.Context(), client.ObjectKey{Namespace: namespace, Name: "pull-request-gitea"}, appSet))
			assert.Equal(t, test.expectedRefresh, appSet.RefreshRequired())
		})
	}
}

// TestGetPRGeneratorInfoGitea checks which Gitea pull request actions trigger a refresh.
// The action values are the ones Gitea sends, see modules/structs/hook.go in go-gitea/gitea.
func TestGetPRGeneratorInfoGitea(t *testing.T) {
	t.Parallel()
	eventJSON, err := os.ReadFile(filepath.Join("testdata", "gitea-pull-request-opened-event.json"))
	require.NoError(t, err)

	tests := []struct {
		action          string
		expectedRefresh bool
	}{
		{action: "opened", expectedRefresh: true},
		{action: "closed", expectedRefresh: true},
		{action: "reopened", expectedRefresh: true},
		{action: "synchronized", expectedRefresh: true},
		{action: "label_updated", expectedRefresh: true},
		{action: "label_cleared", expectedRefresh: true},
		{action: "edited", expectedRefresh: false},
		{action: "deleted", expectedRefresh: false},
		{action: "assigned", expectedRefresh: false},
		{action: "unassigned", expectedRefresh: false},
		{action: "milestoned", expectedRefresh: false},
		{action: "demilestoned", expectedRefresh: false},
		{action: "reviewed", expectedRefresh: false},
		{action: "review_requested", expectedRefresh: false},
		{action: "review_request_removed", expectedRefresh: false},
		// GitHub names of the same actions
		{action: "synchronize", expectedRefresh: false},
		{action: "labeled", expectedRefresh: false},
		{action: "unlabeled", expectedRefresh: false},
	}
	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			t.Parallel()
			var payload gogsclient.PullRequestPayload
			require.NoError(t, json.Unmarshal(eventJSON, &payload))
			payload.Action = gogsclient.HookIssueAction(test.action)

			info := getPRGeneratorInfo(payload)
			if !test.expectedRefresh {
				assert.Nil(t, info)
				return
			}
			require.NotNil(t, info)
			assert.Equal(t, &prGeneratorGiteaInfo{Owner: "Codertocat", Repo: "Hello-World", APIHostname: "gitea"}, info.Gitea)
			assert.Nil(t, info.Github)
		})
	}

	t.Run("owner from the legacy username field", func(t *testing.T) {
		t.Parallel()
		payload := gogsclient.PullRequestPayload{
			Action: gogsclient.HOOK_ISSUE_OPENED,
			Repository: &gogsclient.Repository{
				Owner:   &gogsclient.User{UserName: "Codertocat"},
				Name:    "Hello-World",
				HTMLURL: "https://gogs.example.com/Codertocat/Hello-World",
			},
		}
		info := getPRGeneratorInfo(payload)
		require.NotNil(t, info)
		assert.Equal(t, &prGeneratorGiteaInfo{Owner: "Codertocat", Repo: "Hello-World", APIHostname: "gogs.example.com"}, info.Gitea)
	})

	t.Run("event without a repository", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, getPRGeneratorInfo(gogsclient.PullRequestPayload{Action: gogsclient.HOOK_ISSUE_OPENED}))
	})
}

// TestGetGitGeneratorInfoGitea checks the push event Gitea sends in the Gogs format.
func TestGetGitGeneratorInfoGitea(t *testing.T) {
	t.Parallel()
	eventJSON, err := os.ReadFile(filepath.Join("testdata", "gitea-push-event.json"))
	require.NoError(t, err)

	var payload gogsclient.PushPayload
	require.NoError(t, json.Unmarshal(eventJSON, &payload))
	info := getGitGeneratorInfo(payload)
	require.NotNil(t, info)
	assert.Equal(t, "dev", info.Revision)
	assert.True(t, info.TouchedHead)
	assert.True(t, info.RepoRegexp.MatchString("http://gitea/Codertocat/Hello-World"))

	t.Run("event without a repository", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, getGitGeneratorInfo(gogsclient.PushPayload{Ref: "refs/heads/main"}))
	})
}

func mockGenerators() map[string]generators.Generator {
	// generatorMockList := generatorMock{}
	generatorMockGit := &generatorMock{}
	generatorMockPR := &generatorMock{}
	generatorMockPlugin := &generatorMock{}
	mockSCMProvider := &scm_provider.MockProvider{
		Repos: []*scm_provider.Repository{
			{
				Organization: "myorg",
				Repository:   "repo1",
				URL:          "git@github.com:org/repo.git",
				Branch:       "main",
				SHA:          "0bc57212c3cbbec69d20b34c507284bd300def5b",
			},
			{
				Organization: "Codertocat",
				Repository:   "Hello-World",
				URL:          "git@github.com:Codertocat/Hello-World.git",
				Branch:       "main",
				SHA:          "59d0",
			},
		},
	}
	generatorMockSCM := generators.NewTestSCMProviderGenerator(mockSCMProvider)

	terminalMockGenerators := map[string]generators.Generator{
		"List":        generators.NewListGenerator(),
		"Git":         generatorMockGit,
		"SCMProvider": generatorMockSCM,
		"PullRequest": generatorMockPR,
		"Plugin":      generatorMockPlugin,
	}

	nestedGenerators := map[string]generators.Generator{
		"List":        terminalMockGenerators["List"],
		"Git":         terminalMockGenerators["Git"],
		"SCMProvider": terminalMockGenerators["SCMProvider"],
		"PullRequest": terminalMockGenerators["PullRequest"],
		"Plugin":      terminalMockGenerators["Plugin"],
		"Matrix":      generators.NewMatrixGenerator(terminalMockGenerators),
		"Merge":       generators.NewMergeGenerator(terminalMockGenerators),
	}

	return map[string]generators.Generator{
		"List":        terminalMockGenerators["List"],
		"Git":         terminalMockGenerators["Git"],
		"SCMProvider": terminalMockGenerators["SCMProvider"],
		"PullRequest": terminalMockGenerators["PullRequest"],
		"Plugin":      terminalMockGenerators["Plugin"],
		"Matrix":      generators.NewMatrixGenerator(nestedGenerators),
		"Merge":       generators.NewMergeGenerator(nestedGenerators),
	}
}

func TestGenRevisionHasChanged(t *testing.T) {
	t.Parallel()
	type args struct {
		gen         *v1alpha1.GitGenerator
		revision    string
		touchedHead bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "touchedHead", args: args{
			gen:         &v1alpha1.GitGenerator{},
			revision:    "main",
			touchedHead: true,
		}, want: true},
		{name: "didntTouchHead", args: args{
			gen:         &v1alpha1.GitGenerator{},
			revision:    "main",
			touchedHead: false,
		}, want: false},
		{name: "foundEqualShort", args: args{
			gen:         &v1alpha1.GitGenerator{Revision: "dev"},
			revision:    "dev",
			touchedHead: true,
		}, want: true},
		{name: "foundEqualLongGen", args: args{
			gen:         &v1alpha1.GitGenerator{Revision: "refs/heads/dev"},
			revision:    "dev",
			touchedHead: true,
		}, want: true},
		{name: "foundNotEqualLongGen", args: args{
			gen:         &v1alpha1.GitGenerator{Revision: "refs/heads/dev"},
			revision:    "main",
			touchedHead: true,
		}, want: false},
		{name: "foundNotEqualShort", args: args{
			gen:         &v1alpha1.GitGenerator{Revision: "dev"},
			revision:    "main",
			touchedHead: false,
		}, want: false},
		{name: "foundEqualTag", args: args{
			gen:         &v1alpha1.GitGenerator{Revision: "v3.14.1"},
			revision:    "v3.14.1",
			touchedHead: false,
		}, want: true},
		{name: "foundEqualTagLongGen", args: args{
			gen:         &v1alpha1.GitGenerator{Revision: "refs/tags/v3.14.1"},
			revision:    "v3.14.1",
			touchedHead: false,
		}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equalf(t, tt.want, genRevisionHasChanged(tt.args.gen, tt.args.revision, tt.args.touchedHead), "genRevisionHasChanged(%v, %v, %v)", tt.args.gen, tt.args.revision, tt.args.touchedHead)
		})
	}
}

func fakeAppWithGitGenerator(name, namespace, repo string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					Git: &v1alpha1.GitGenerator{
						RepoURL:  repo,
						Revision: "master",
					},
				},
			},
		},
	}
}

func fakeAppWithGitGeneratorWithRevision(name, namespace, repo, revision string) *v1alpha1.ApplicationSet {
	appSet := fakeAppWithGitGenerator(name, namespace, repo)
	appSet.Spec.Generators[0].Git.Revision = revision
	return appSet
}

func fakeAppWithGitlabPullRequestGenerator(name, namespace, projectId string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					PullRequest: &v1alpha1.PullRequestGenerator{
						GitLab: &v1alpha1.PullRequestGeneratorGitLab{
							Project: projectId,
						},
					},
				},
			},
		},
	}
}

func fakeAppWithGithubPullRequestGenerator(name, namespace, owner, repo string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					PullRequest: &v1alpha1.PullRequestGenerator{
						Github: &v1alpha1.PullRequestGeneratorGithub{
							Owner: owner,
							Repo:  repo,
						},
					},
				},
			},
		},
	}
}

func fakeAppWithGiteaPullRequestGenerator(name, namespace, owner, repo, api string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					PullRequest: &v1alpha1.PullRequestGenerator{
						Gitea: &v1alpha1.PullRequestGeneratorGitea{
							Owner: owner,
							Repo:  repo,
							API:   api,
						},
					},
				},
			},
		},
	}
}

// giteaHeaders returns the headers Gitea sends with a webhook delivery, see
// addDefaultHeaders in services/webhook/deliver.go of go-gitea/gitea. Besides its
// own headers, Gitea sends the Gogs and GitHub ones with the same event and
// signatures. Without a secret the signatures are empty, as Gitea sends them.
func giteaHeaders(event, eventType, secret string, body []byte) map[string]string {
	var signatureSHA1, signatureSHA256 string
	if secret != "" {
		sig1 := hmac.New(sha1.New, []byte(secret))
		sig1.Write(body)
		signatureSHA1 = hex.EncodeToString(sig1.Sum(nil))
		sig256 := hmac.New(sha256.New, []byte(secret))
		sig256.Write(body)
		signatureSHA256 = hex.EncodeToString(sig256.Sum(nil))
	}
	const delivery = "3c4f6a9e-2b1d-4c8e-9f7a-5d6b8c0e1f23"
	return map[string]string{
		"X-Gitea-Delivery":                       delivery,
		"X-Gitea-Event":                          event,
		"X-Gitea-Event-Type":                     eventType,
		"X-Gitea-Signature":                      signatureSHA256,
		"X-Gitea-Hook-Installation-Target-Type":  "repository",
		"X-Gogs-Delivery":                        delivery,
		"X-Gogs-Event":                           event,
		"X-Gogs-Event-Type":                      eventType,
		"X-Gogs-Signature":                       signatureSHA256,
		"X-Hub-Signature":                        "sha1=" + signatureSHA1,
		"X-Hub-Signature-256":                    "sha256=" + signatureSHA256,
		"X-GitHub-Delivery":                      delivery,
		"X-GitHub-Event":                         event,
		"X-GitHub-Event-Type":                    eventType,
		"X-GitHub-Hook-Installation-Target-Type": "repository",
	}
}

func fakeAppWithAzureDevOpsPullRequestGenerator(name, namespace, project, repo string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					PullRequest: &v1alpha1.PullRequestGenerator{
						AzureDevOps: &v1alpha1.PullRequestGeneratorAzureDevOps{
							Project: project,
							Repo:    repo,
						},
					},
				},
			},
		},
	}
}

func fakeAppWithMatrixAndGitGenerator(name, namespace, repo string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					Matrix: &v1alpha1.MatrixGenerator{
						Generators: []v1alpha1.ApplicationSetNestedGenerator{
							{
								List: &v1alpha1.ListGenerator{},
							},
							{
								Git: &v1alpha1.GitGenerator{
									RepoURL: repo,
								},
							},
						},
					},
				},
			},
		},
	}
}

func fakeAppWithMatrixAndPullRequestGenerator(name, namespace, owner, repo string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					Matrix: &v1alpha1.MatrixGenerator{
						Generators: []v1alpha1.ApplicationSetNestedGenerator{
							{
								List: &v1alpha1.ListGenerator{},
							},
							{
								PullRequest: &v1alpha1.PullRequestGenerator{
									Github: &v1alpha1.PullRequestGeneratorGithub{
										Owner: owner,
										Repo:  repo,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func fakeAppWithMatrixAndScmWithGitGenerator(name, namespace, owner string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					Matrix: &v1alpha1.MatrixGenerator{
						Generators: []v1alpha1.ApplicationSetNestedGenerator{
							{
								SCMProvider: &v1alpha1.SCMProviderGenerator{
									CloneProtocol: "ssh",
									Github: &v1alpha1.SCMProviderGeneratorGithub{
										Organization: owner,
									},
								},
							},
							{
								Git: &v1alpha1.GitGenerator{
									RepoURL: "{{ url }}",
								},
							},
						},
					},
				},
			},
		},
	}
}

func fakeAppWithMatrixAndScmWithPullRequestGenerator(name, namespace, owner string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					Matrix: &v1alpha1.MatrixGenerator{
						Generators: []v1alpha1.ApplicationSetNestedGenerator{
							{
								SCMProvider: &v1alpha1.SCMProviderGenerator{
									CloneProtocol: "https",
									Github: &v1alpha1.SCMProviderGeneratorGithub{
										Organization: owner,
									},
								},
							},
							{
								PullRequest: &v1alpha1.PullRequestGenerator{
									Github: &v1alpha1.PullRequestGeneratorGithub{
										Owner: "{{ organization }}",
										Repo:  "{{ repository }}",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func fakeAppWithMatrixAndNestedGitGenerator(name, namespace, repo string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					Matrix: &v1alpha1.MatrixGenerator{
						Generators: []v1alpha1.ApplicationSetNestedGenerator{
							{
								List: &v1alpha1.ListGenerator{},
							},
							{
								Matrix: &apiextensionsv1.JSON{
									Raw: fmt.Appendf(nil, `{
										"Generators": [
											{
												"List": {
													"Elements": [
														{
															"repository": "%s"
														}
													]
												}
											},
											{
												"Git": {
													"RepoURL": "{{ repository }}"
												}
											}
										]
									}`, repo),
								},
							},
						},
					},
				},
			},
		},
	}
}

func fakeAppWithMergeAndGitGenerator(name, namespace, repo string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					Merge: &v1alpha1.MergeGenerator{
						Generators: []v1alpha1.ApplicationSetNestedGenerator{
							{
								Git: &v1alpha1.GitGenerator{
									RepoURL: repo,
								},
							},
						},
					},
				},
			},
		},
	}
}

func fakeAppWithMergeAndPullRequestGenerator(name, namespace, owner, repo string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					Merge: &v1alpha1.MergeGenerator{
						Generators: []v1alpha1.ApplicationSetNestedGenerator{
							{
								PullRequest: &v1alpha1.PullRequestGenerator{
									Github: &v1alpha1.PullRequestGeneratorGithub{
										Owner: owner,
										Repo:  repo,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func fakeAppWithMergeAndNestedGitGenerator(name, namespace, repo string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					Merge: &v1alpha1.MergeGenerator{
						MergeKeys: []string{
							"server",
						},
						Generators: []v1alpha1.ApplicationSetNestedGenerator{
							{
								List: &v1alpha1.ListGenerator{},
							},
							{
								Merge: &apiextensionsv1.JSON{
									Raw: fmt.Appendf(nil, `{
										"MergeKeys": ["server"],
										"Generators": [
											{
												"List": {}
											},
											{
												"Git": {
													"RepoURL": "%s"
												}
											}
										]
									}`, repo),
								},
							},
						},
					},
				},
			},
		},
	}
}

func fakeAppWithPluginGenerator(name, namespace string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					Plugin: &v1alpha1.PluginGenerator{
						ConfigMapRef: v1alpha1.PluginConfigMapRef{
							Name: "test",
						},
					},
				},
			},
		},
	}
}

func fakeAppWithMatrixAndPullRequestGeneratorWithPluginGenerator(name, namespace, owner, repo, configmapName string) *v1alpha1.ApplicationSet {
	return &v1alpha1.ApplicationSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.ApplicationSetSpec{
			Generators: []v1alpha1.ApplicationSetGenerator{
				{
					Matrix: &v1alpha1.MatrixGenerator{
						Generators: []v1alpha1.ApplicationSetNestedGenerator{
							{
								PullRequest: &v1alpha1.PullRequestGenerator{
									Github: &v1alpha1.PullRequestGeneratorGithub{
										Owner: owner,
										Repo:  repo,
									},
								},
							},
							{
								Plugin: &v1alpha1.PluginGenerator{
									ConfigMapRef: v1alpha1.PluginConfigMapRef{
										Name: configmapName,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func newFakeClient(ns string) *kubefake.Clientset {
	return newFakeClientWithSettings(ns, nil)
}

func newFakeClientWithSettings(ns string, secretData map[string][]byte) *kubefake.Clientset {
	data := map[string][]byte{
		"server.secretkey": nil,
	}
	maps.Copy(data, secretData)
	s := runtime.NewScheme()
	s.AddKnownTypes(v1alpha1.SchemeGroupVersion, &v1alpha1.ApplicationSet{})
	return kubefake.NewClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "argocd-cm", Namespace: ns, Labels: map[string]string{
		"app.kubernetes.io/part-of": "argocd",
	}}}, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.ArgoCDSecretName,
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/part-of": "argocd",
			},
		},
		Data: data,
	})
}
