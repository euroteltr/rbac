package rbac

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestConsoleLogger(t *testing.T) {
	var buf bytes.Buffer
	old := os.Stdout // keep backup of the real stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := NewConsoleLogger()
	logger.Debugf("debug")
	logger.Errorf("error")

	outC := make(chan string)
	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	w.Close()
	os.Stdout = old // restoring the real stdout
	_ = <-outC
	expected := "[DEBUG] debug\n[ERROR] error\n"
	if string(buf.Bytes()) != expected {
		t.Fatalf("logger output is not compatible, expected: `%s`, got: `%s`", expected, buf.Bytes())
	}
}

func TestNullLogger(t *testing.T) {
	var buf bytes.Buffer
	old := os.Stdout // keep backup of the real stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := NewNullLogger()
	logger.Debugf("TEST")
	logger.Errorf("TEST2")

	outC := make(chan string)
	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	w.Close()
	os.Stdout = old // restoring the real stdout
	_ = <-outC

	if string(buf.Bytes()) != "" {
		t.Fatalf("logger output is not compatible, expected: `%s`, got: `%s`", "", buf.Bytes())
	}
}

func TestDefaultLogger(t *testing.T) {
	var buf bytes.Buffer
	old := os.Stdout // keep backup of the real stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	logger := NewNullLogger()
	SetLogger(logger)
	log.Debugf("TEST")
	log.Errorf("TEST2")

	outC := make(chan string)
	// copy the output in a separate goroutine so printing can't block indefinitely
	go func() {
		io.Copy(&buf, r)
		outC <- buf.String()
	}()

	w.Close()
	os.Stdout = old // restoring the real stdout
	_ = <-outC

	if string(buf.Bytes()) != "" {
		t.Fatalf("logger output is not compatible, expected: `%s`, got: `%s`", "", buf.Bytes())
	}
}
