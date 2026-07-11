package approve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// logf writes an operational line about the approver to stderr, matching the
// guard's other stderr diagnostics. Silent failures on the approval path (a
// getUpdates error, a tap that doesn't resolve) are impossible to diagnose
// otherwise.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[approve/telegram] "+format+"\n", args...)
}

// defaultTelegramBaseURL is the public Bot API host. Tests inject an
// httptest.Server URL in its place; production leaves it empty (→ this default).
const defaultTelegramBaseURL = "https://api.telegram.org"

// maxMessageText is Telegram's hard cap on sendMessage text (4096 chars). We
// bound our composed prompt well under it so a pathological Reason can never
// make the API reject the whole notification.
const maxMessageText = 4096

// requestTimeout bounds every one-shot Bot API call (sendMessage,
// answerCallbackQuery). getUpdates uses its own long-poll timeout below.
const telegramRequestTimeout = 10 * time.Second

// longPollSeconds is the getUpdates long-poll window. The HTTP client timeout
// must exceed this so the request isn't cancelled mid-poll.
const longPollSeconds = 25

// Telegram notifies the owner of a pending approval and long-polls for their
// tap. Notify posts a sendMessage with inline Approve/Deny buttons; Poll runs a
// getUpdates loop that turns a button tap into a resolve(id, verdict, who) call
// and answers the callback query to clear the client-side spinner.
//
// It imports the standard library only and never panics on malformed updates.
type Telegram struct {
	botToken string
	chatID   string
	baseURL  string
	client   *http.Client
}

// NewTelegram builds a Telegram client for botToken posting to chatID. baseURL
// is injectable for tests; an empty baseURL uses the public Bot API host. The
// getUpdates client has no overall timeout (the loop bounds each poll itself);
// one-shot calls use their own short-timeout client.
func NewTelegram(botToken, chatID, baseURL string) *Telegram {
	if baseURL == "" {
		baseURL = defaultTelegramBaseURL
	}
	return &Telegram{
		botToken: botToken,
		chatID:   chatID,
		baseURL:  strings.TrimRight(baseURL, "/"),
		client:   &http.Client{},
	}
}

// method returns the full Bot API URL for a method name, e.g.
// https://api.telegram.org/bot<token>/sendMessage.
func (t *Telegram) method(name string) string {
	return fmt.Sprintf("%s/bot%s/%s", t.baseURL, t.botToken, name)
}

// inlineButton is one inline-keyboard button.
type inlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// sendMessageRequest is the JSON body POSTed to sendMessage.
type sendMessageRequest struct {
	ChatID      string `json:"chat_id"`
	Text        string `json:"text"`
	ReplyMarkup struct {
		InlineKeyboard [][]inlineButton `json:"inline_keyboard"`
	} `json:"reply_markup"`
}

// Notify posts a sendMessage describing the pending action with two inline
// buttons: Approve (callback_data "<id>:allow") and Deny ("<id>:deny"). A
// non-2xx response or transport error is returned so the caller can fall back
// to the console inbox.
func (t *Telegram) Notify(p Pending) error {
	req := sendMessageRequest{
		ChatID: t.chatID,
		Text:   notifyText(p),
	}
	req.ReplyMarkup.InlineKeyboard = [][]inlineButton{{
		{Text: "✅ Approve", CallbackData: p.DecisionID + ":" + VerdictAllow},
		{Text: "⛔ Deny", CallbackData: p.DecisionID + ":" + VerdictDeny},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), telegramRequestTimeout)
	defer cancel()
	return t.post(ctx, t.method("sendMessage"), req)
}

// notifyText composes a short, human-readable prompt naming the agent, surface,
// verb and reason. The whole message is bounded to Telegram's text cap.
func notifyText(p Pending) string {
	var b strings.Builder
	b.WriteString("Approval needed\n\n")
	fmt.Fprintf(&b, "agent: %s\n", p.Principal)
	fmt.Fprintf(&b, "action: %s %s\n", p.Surface, p.Verb)
	if p.Reason != "" {
		fmt.Fprintf(&b, "reason: %s\n", p.Reason)
	}
	fmt.Fprintf(&b, "id: %s", p.DecisionID)
	return boundText(b.String(), maxMessageText)
}

// boundText truncates s to at most n runes, appending an ellipsis marker when it
// had to cut. Rune-aware so multibyte text isn't split mid-character.
func boundText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// answerCallbackRequest clears the spinner on a tapped inline button and shows a
// short toast (Text) so the owner gets immediate feedback that the tap landed.
type answerCallbackRequest struct {
	CallbackQueryID string `json:"callback_query_id"`
	Text            string `json:"text,omitempty"`
}

// editMessageRequest rewrites the original approval message to its outcome and
// drops the buttons (an empty inline_keyboard), so the resolved state is visible
// and can't be tapped again.
type editMessageRequest struct {
	ChatID      string `json:"chat_id"`
	MessageID   int64  `json:"message_id"`
	Text        string `json:"text"`
	ReplyMarkup struct {
		InlineKeyboard [][]inlineButton `json:"inline_keyboard"`
	} `json:"reply_markup"`
}

// getUpdatesRequest long-polls for new updates past offset.
type getUpdatesRequest struct {
	Offset  int64 `json:"offset"`
	Timeout int   `json:"timeout"`
}

// update is the subset of a Telegram Update we care about: a callback_query
// from a tapped inline button. Message/other update kinds are ignored.
type update struct {
	UpdateID      int64 `json:"update_id"`
	CallbackQuery *struct {
		ID   string `json:"id"`
		From struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
		} `json:"from"`
		Message *struct {
			MessageID int64 `json:"message_id"`
		} `json:"message"`
		Data string `json:"data"`
	} `json:"callback_query"`
}

// getUpdatesResponse is the Bot API envelope for getUpdates.
type getUpdatesResponse struct {
	OK     bool     `json:"ok"`
	Result []update `json:"result"`
}

// Poll runs the getUpdates long-poll loop until ctx is cancelled. For each
// callback_query it parses "<id>:<verdict>", calls resolve(id, verdict, who)
// (who = username, else numeric user id), and answers the callback query. The
// offset advances past each consumed update so it is delivered once. Transport
// errors and malformed updates are skipped without panicking; the loop backs
// off briefly on error to avoid a hot spin.
func (t *Telegram) Poll(ctx context.Context, resolve func(id, verdict, who string) bool) {
	var offset int64
	for {
		if ctx.Err() != nil {
			return
		}
		updates, err := t.getUpdates(ctx, offset)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logf("getUpdates error (retrying): %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		for _, u := range updates {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			t.handleUpdate(ctx, u, resolve)
		}
	}
}

// handleUpdate processes a single update: a valid callback_query drives resolve
// then answers the query. Anything malformed is ignored.
func (t *Telegram) handleUpdate(ctx context.Context, u update, resolve func(id, verdict, who string) bool) {
	if u.CallbackQuery == nil {
		return
	}
	id, verdict, ok := parseCallbackData(u.CallbackQuery.Data)
	if !ok {
		return
	}
	who := u.CallbackQuery.From.Username
	if who == "" {
		who = strconv.FormatInt(u.CallbackQuery.From.ID, 10)
	}
	won := resolve(id, verdict, who)
	logf("tap received id=%s verdict=%s who=%s resolved=%v", id, verdict, who, won)

	// Give the owner immediate, visible feedback. Without this the tap silently
	// clears the spinner and the message is unchanged, so it looks like nothing
	// happened. A toast confirms the tap; on the winning tap we also rewrite the
	// message to the outcome and drop the buttons. A tap that lost the race (or
	// hit an already-resolved item) gets an "already decided" toast.
	toast := "Already decided"
	outcome := ""
	if won {
		if verdict == VerdictAllow {
			toast, outcome = "Approved ✅", "✅ Approved by you"
		} else {
			toast, outcome = "Denied ⛔", "⛔ Denied by you"
		}
	}

	actx, cancel := context.WithTimeout(ctx, telegramRequestTimeout)
	defer cancel()
	// Best-effort throughout: feedback failing never undoes the resolution.
	_ = t.post(actx, t.method("answerCallbackQuery"), answerCallbackRequest{
		CallbackQueryID: u.CallbackQuery.ID,
		Text:            toast,
	})
	if won && u.CallbackQuery.Message != nil && u.CallbackQuery.Message.MessageID != 0 {
		edit := editMessageRequest{
			ChatID:    t.chatID,
			MessageID: u.CallbackQuery.Message.MessageID,
			Text:      outcome,
		}
		_ = t.post(actx, t.method("editMessageText"), edit)
	}
}

// parseCallbackData splits "<id>:<verdict>" and validates the verdict against
// the store's allow/deny constants. A missing colon, empty id, or unknown
// verdict returns ok=false so a malformed tap is a no-op.
func parseCallbackData(data string) (id, verdict string, ok bool) {
	i := strings.LastIndex(data, ":")
	if i <= 0 || i == len(data)-1 {
		return "", "", false
	}
	id = data[:i]
	verdict = data[i+1:]
	if verdict != VerdictAllow && verdict != VerdictDeny {
		return "", "", false
	}
	return id, verdict, true
}

// getUpdates issues one long-poll getUpdates request past offset. It uses a
// per-request context bounded to just over the long-poll window so a hung
// server can't wedge the loop forever, while still respecting ctx cancel.
func (t *Telegram) getUpdates(ctx context.Context, offset int64) ([]update, error) {
	rctx, cancel := context.WithTimeout(ctx, (longPollSeconds+5)*time.Second)
	defer cancel()

	body, err := json.Marshal(getUpdatesRequest{Offset: offset, Timeout: longPollSeconds})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, t.method("getUpdates"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("telegram getUpdates: status %d", resp.StatusCode)
	}

	var out getUpdatesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

// post marshals v as JSON, POSTs it to url, and returns an error for a non-2xx
// status or transport/encoding failure. The response body is drained and closed
// so the connection can be reused.
func (t *Telegram) post(ctx context.Context, url string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram %s: status %d", url, resp.StatusCode)
	}
	return nil
}
