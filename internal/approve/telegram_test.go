package approve

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// sendMessagePayload mirrors the fields we assert on the Telegram sendMessage
// request body.
type sendMessagePayload struct {
	ChatID      string `json:"chat_id"`
	Text        string `json:"text"`
	ReplyMarkup struct {
		InlineKeyboard [][]struct {
			Text         string `json:"text"`
			CallbackData string `json:"callback_data"`
		} `json:"inline_keyboard"`
	} `json:"reply_markup"`
}

func TestNotifyPostsSendMessage(t *testing.T) {
	var got sendMessagePayload
	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("decode sendMessage body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer srv.Close()

	tg := NewTelegram("BOT123", "chat-42", srv.URL)
	p := newPending("d1", time.Minute)
	if err := tg.Notify(p); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if want := "/botBOT123/sendMessage"; gotPath != want {
		t.Fatalf("sendMessage path: want %q, got %q", want, gotPath)
	}
	if got.ChatID != "chat-42" {
		t.Fatalf("chat_id: want chat-42, got %q", got.ChatID)
	}
	// The text should describe what's being asked.
	for _, want := range []string{p.Principal, p.Surface, p.Verb, p.Reason} {
		if !strings.Contains(got.Text, want) {
			t.Fatalf("text %q missing %q", got.Text, want)
		}
	}

	// Two buttons: allow + deny, callback_data "<id>:<verdict>".
	var buttons []struct {
		Text         string
		CallbackData string
	}
	for _, row := range got.ReplyMarkup.InlineKeyboard {
		for _, b := range row {
			buttons = append(buttons, struct {
				Text         string
				CallbackData string
			}{b.Text, b.CallbackData})
		}
	}
	if len(buttons) != 2 {
		t.Fatalf("inline_keyboard: want 2 buttons, got %d (%+v)", len(buttons), buttons)
	}
	haveAllow, haveDeny := false, false
	for _, b := range buttons {
		switch b.CallbackData {
		case "d1:allow":
			haveAllow = true
		case "d1:deny":
			haveDeny = true
		}
	}
	if !haveAllow || !haveDeny {
		t.Fatalf("callback_data: want d1:allow and d1:deny, got %+v", buttons)
	}
}

func TestNotifyNon2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
	}))
	defer srv.Close()

	tg := NewTelegram("BOT123", "chat-42", srv.URL)
	if err := tg.Notify(newPending("d1", time.Minute)); err == nil {
		t.Fatalf("Notify against 401: want error, got nil")
	}
}

func TestNotifyBoundsLongReason(t *testing.T) {
	var got sendMessagePayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	p := newPending("d1", time.Minute)
	p.Reason = strings.Repeat("A", 8000)
	tg := NewTelegram("BOT123", "chat-42", srv.URL)
	if err := tg.Notify(p); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	// Telegram caps message text at 4096; we must stay under it.
	if len([]rune(got.Text)) > 4096 {
		t.Fatalf("text length: want <= 4096, got %d", len([]rune(got.Text)))
	}
}

// TestPollDrivesResolveOnCallback simulates getUpdates returning a single
// callback_query carrying "d1:allow"; the poller must call resolve exactly once
// with that id/verdict and answer the callback query.
func TestPollDrivesResolveOnCallback(t *testing.T) {
	var (
		mu             sync.Mutex
		answeredCB     string
		sentUpdate     atomic.Bool
		lastOffset     atomic.Int64
		getUpdatesSeen atomic.Int64
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			getUpdatesSeen.Add(1)
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Offset int64 `json:"offset"`
			}
			_ = json.Unmarshal(body, &req)
			lastOffset.Store(req.Offset)

			// Serve the callback once; afterwards return an empty batch so the
			// loop keeps polling harmlessly until ctx is cancelled.
			if sentUpdate.CompareAndSwap(false, true) {
				_, _ = w.Write([]byte(`{"ok":true,"result":[{
					"update_id": 100,
					"callback_query": {
						"id": "cb1",
						"from": {"id": 7, "username": "owner"},
						"message": {"message_id": 555},
						"data": "d1:allow"
					}
				}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))

		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			body, _ := io.ReadAll(r.Body)
			var req struct {
				CallbackQueryID string `json:"callback_query_id"`
			}
			_ = json.Unmarshal(body, &req)
			mu.Lock()
			answeredCB = req.CallbackQueryID
			mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))

		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	type call struct {
		id, verdict, who string
	}
	calls := make(chan call, 4)
	resolve := func(id, verdict, who string) bool {
		calls <- call{id, verdict, who}
		return true
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tg := NewTelegram("BOT123", "chat-42", srv.URL)
	done := make(chan struct{})
	go func() {
		tg.Poll(ctx, resolve, func(string) (string, bool) { return "", false })
		close(done)
	}()

	select {
	case c := <-calls:
		if c.id != "d1" || c.verdict != "allow" {
			t.Fatalf("resolve: want d1/allow, got %s/%s", c.id, c.verdict)
		}
		if c.who != "owner" {
			t.Fatalf("resolve who: want owner, got %q", c.who)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("resolve was not called within 2s")
	}

	// resolve must fire exactly once for that update.
	select {
	case c := <-calls:
		t.Fatalf("resolve called again unexpectedly: %+v", c)
	case <-time.After(200 * time.Millisecond):
	}

	// The callback query must have been answered to clear the spinner.
	mu.Lock()
	ans := answeredCB
	mu.Unlock()
	if ans != "cb1" {
		t.Fatalf("answerCallbackQuery: want cb1, got %q", ans)
	}

	// Offset must have advanced past the consumed update (update_id+1).
	if got := lastOffset.Load(); got != 101 {
		t.Fatalf("getUpdates offset: want 101 after update 100, got %d", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Poll did not return after ctx cancel")
	}
}

// TestPollIgnoresMalformedUpdates ensures a malformed callback (no colon,
// missing fields) never panics and never calls resolve.
func TestPollIgnoresMalformedUpdates(t *testing.T) {
	var served atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/getUpdates") && served.CompareAndSwap(false, true) {
			_, _ = w.Write([]byte(`{"ok":true,"result":[
				{"update_id": 1, "message": {"text":"not a callback"}},
				{"update_id": 2, "callback_query": {"id":"cb","from":{"id":9},"data":"nocolon"}},
				{"update_id": 3, "callback_query": {"id":"cb","from":{"id":9},"data":""}}
			]}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
	}))
	defer srv.Close()

	resolved := make(chan struct{}, 1)
	resolve := func(id, verdict, who string) bool {
		resolved <- struct{}{}
		return true
	}

	ctx, cancel := context.WithCancel(context.Background())
	tg := NewTelegram("BOT123", "chat-42", srv.URL)
	done := make(chan struct{})
	go func() {
		tg.Poll(ctx, resolve, func(string) (string, bool) { return "", false })
		close(done)
	}()

	select {
	case <-resolved:
		t.Fatal("resolve called on malformed updates")
	case <-time.After(400 * time.Millisecond):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Poll did not return after ctx cancel")
	}
}

// TestPollTapGivesFeedback proves a tap gets visible feedback: answerCallbackQuery
// is called WITH a toast text, and the original message is rewritten via
// editMessageText to the outcome. Without this the tap looked like a no-op.
func TestPollTapGivesFeedback(t *testing.T) {
	var (
		mu         sync.Mutex
		answerText string
		editedID   int64
		editedText string
		editRaw    string
		editCalled = make(chan struct{}, 1)
		sentUpdate atomic.Bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			if sentUpdate.CompareAndSwap(false, true) {
				_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":100,"callback_query":{"id":"cb1","from":{"id":7,"username":"owner"},"message":{"message_id":555},"data":"d1:allow"}}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(body, &req)
			mu.Lock()
			answerText = req.Text
			mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			body, _ := io.ReadAll(r.Body)
			var req struct {
				MessageID int64  `json:"message_id"`
				Text      string `json:"text"`
			}
			_ = json.Unmarshal(body, &req)
			mu.Lock()
			editedID = req.MessageID
			editedText = req.Text
			editRaw = string(body)
			mu.Unlock()
			select {
			case editCalled <- struct{}{}:
			default:
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tg := NewTelegram("BOT123", "chat-42", srv.URL)
	go tg.Poll(ctx, func(id, verdict, who string) bool { return true }, func(string) (string, bool) { return VerdictAllow, true })

	select {
	case <-editCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("editMessageText was not called within 2s")
	}
	mu.Lock()
	defer mu.Unlock()
	if answerText == "" {
		t.Errorf("answerCallbackQuery: want a toast text, got empty")
	}
	if editedID != 555 {
		t.Errorf("editMessageText message_id: want 555, got %d", editedID)
	}
	if !strings.Contains(strings.ToLower(editedText), "approv") {
		t.Errorf("edited text: want an approved outcome, got %q", editedText)
	}
	// The buttons must be removed via an EMPTY inline_keyboard array; a nil slice
	// serializes to "null", which Telegram rejects (Bad Request), leaving the
	// buttons and making the tap look like it did nothing. Regression guard.
	if !strings.Contains(editRaw, `"inline_keyboard":[]`) {
		t.Errorf("editMessageText must send inline_keyboard:[] (not null) to drop buttons; got body %s", editRaw)
	}
}

// TestPollLateTapStillEdits is the regression for "everything says already
// decided and the message never changes": a tap that LOST the race (resolve→false)
// must still rewrite the message to the standing verdict and drop the buttons.
func TestPollLateTapStillEdits(t *testing.T) {
	var (
		mu         sync.Mutex
		editRaw    string
		editCalled = make(chan struct{}, 1)
		sent       atomic.Bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			if sent.CompareAndSwap(false, true) {
				_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":100,"callback_query":{"id":"cb1","from":{"id":7,"username":"owner"},"message":{"message_id":99},"data":"d1:allow"}}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			editRaw = string(body)
			mu.Unlock()
			select {
			case editCalled <- struct{}{}:
			default:
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tg := NewTelegram("BOT", "chat", srv.URL)
	// resolve loses the race; status says it already stands as deny (e.g. a timeout).
	go tg.Poll(ctx,
		func(id, verdict, who string) bool { return false },
		func(id string) (string, bool) { return VerdictDeny, true })

	select {
	case <-editCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("a late tap must still edit the message, but editMessageText was not called")
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(editRaw, `"inline_keyboard":[]`) {
		t.Errorf("late-tap edit must drop buttons via inline_keyboard:[]; got %s", editRaw)
	}
	if !strings.Contains(strings.ToLower(editRaw), "denied") {
		t.Errorf("late-tap edit should show the standing (denied) verdict; got %s", editRaw)
	}
}

func TestNewTelegramDefaultsBaseURL(t *testing.T) {
	tg := NewTelegram("BOT", "chat", "")
	if tg.baseURL != defaultTelegramBaseURL {
		t.Fatalf("default baseURL: want %q, got %q", defaultTelegramBaseURL, tg.baseURL)
	}
}
