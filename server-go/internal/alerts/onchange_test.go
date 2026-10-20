// onchange_test.go - notificación de mutaciones del feed (#1434).
package alerts

import "testing"

func testEvent(id string) AlertEvent {
	return AlertEvent{
		ID:       id,
		Category: CatClients,
		Severity: "warn",
		Title:    "t " + id,
		Time:     "just now",
	}
}

func TestOnChangeMarkReadFiresOnlyOnChange(t *testing.T) {
	e := New(nil, nil)
	e.Emit(testEvent("a"))
	calls := 0
	e.SetOnChange(func() { calls++ })

	e.MarkRead("a")
	if calls != 1 {
		t.Fatalf("mark-read nuevo: 1 llamada, hay %d", calls)
	}
	e.MarkRead("a")
	if calls != 1 {
		t.Fatalf("mark-read idempotente no re-dispara: hay %d", calls)
	}
	e.MarkRead("inexistente")
	if calls != 1 {
		t.Fatalf("mark-read de ID ajeno no dispara: hay %d", calls)
	}
}

func TestOnChangeDismiss(t *testing.T) {
	e := New(nil, nil)
	e.Emit(testEvent("a"))
	calls := 0
	e.SetOnChange(func() { calls++ })

	e.Dismiss("a")
	if calls != 1 {
		t.Fatalf("dismiss de alerta visible: 1 llamada, hay %d", calls)
	}
	e.Dismiss("a")
	if calls != 1 {
		t.Fatalf("dismiss repetido no re-dispara: hay %d", calls)
	}
}

func TestOnChangeDismissAll(t *testing.T) {
	e := New(nil, nil)
	e.Emit(testEvent("a"))
	e.Emit(testEvent("b"))
	calls := 0
	e.SetOnChange(func() { calls++ })

	e.DismissAll()
	if calls == 0 {
		t.Fatal("dismiss-all dispara al menos una notificación")
	}
}

func TestOnChangeResolveOnlyWhenFound(t *testing.T) {
	e := New(nil, nil)
	e.Emit(testEvent("a"))
	calls := 0
	e.SetOnChange(func() { calls++ })

	e.Resolve("inexistente")
	if calls != 0 {
		t.Fatalf("resolve de ID ausente no dispara: hay %d", calls)
	}
	e.Resolve("a")
	if calls != 1 {
		t.Fatalf("resolve de alerta visible dispara: hay %d", calls)
	}
}

func TestOnChangeSilenceUnsilence(t *testing.T) {
	e := New(nil, nil)
	e.Emit(testEvent("a"))
	calls := 0
	e.SetOnChange(func() { calls++ })

	if e.Silence("inexistente", 0) != "" {
		t.Fatal("silence de ID ausente devuelve vacío")
	}
	if calls != 0 {
		t.Fatalf("silence de ID ausente no dispara: hay %d", calls)
	}
	if e.Silence("a", 0) == "" {
		t.Fatal("silence de alerta visible devuelve la dedup key")
	}
	e.Unsilence("cat|t|")
	if calls != 2 {
		t.Fatalf("silence+unsilence disparan 2: hay %d", calls)
	}
}

// TestOnChangeCallbackMayReadEngine: el callback se invoca sin e.mu tomado,
// así que el receptor puede leer el engine (es lo que hace el server para
// reemitir el feed por SSE). Sin esta garantía habría deadlock.
func TestOnChangeCallbackMayReadEngine(t *testing.T) {
	e := New(nil, nil)
	e.Emit(testEvent("a"))
	e.SetOnChange(func() {
		_ = e.List()
		_ = e.UnreadCount()
	})
	e.MarkRead("a")
	e.Resolve("a")
	e.Dismiss("a")
}
