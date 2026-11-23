//go:build windows

package enterprise

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This executable acts as a harmless process tree fixture. No certreq, CNG,
// store or AD CS access occurs in these tests.
func TestProcessTreeHelper(t *testing.T) {
	marker := -1
	for i, arg := range os.Args {
		if arg == "--tree-helper" {
			marker = i
			break
		}
	}
	if marker < 0 {
		return
	}
	mode, dir := os.Args[marker+1], os.Args[marker+2]
	switch mode {
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestProcessTreeHelper$", "--", "--tree-helper", "descendant", dir)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		// Deliberately do not wait: the direct child exits first.
		fmt.Print("parent-exit\n")
		os.Exit(0)
	case "descendant":
		if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("ready"), 0600); err != nil {
			os.Exit(3)
		}
		for {
			if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		fmt.Print("descendant-exit\n")
		os.Exit(0)
	case "exit":
		fmt.Print("out\n")
		fmt.Fprint(os.Stderr, "err\n")
		os.Exit(7)
	default:
		os.Exit(4)
	}
}

func waitFixtureReady(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("process fixture did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProcessTreeWaitsForIndirectDescendant(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	type result struct {
		out  string
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		out, _, code, err := runCommandTree(ctx, os.Args[0], "-test.run=^TestProcessTreeHelper$", "--", "--tree-helper", "parent", dir)
		done <- result{out, code, err}
	}()
	waitFixtureReady(t, dir)
	select {
	case result := <-done:
		t.Fatalf("returned before descendant exited: %+v", result)
	default:
	}
	if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil || got.code != 0 || !strings.Contains(got.out, "descendant-exit") {
		t.Fatalf("tree execution: %+v", got)
	}
}

func TestProcessTreeCancellationWaitsForEntireJob(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, _, err := runCommandTree(ctx, os.Args[0], "-test.run=^TestProcessTreeHelper$", "--", "--tree-helper", "parent", dir)
		done <- err
	}()
	waitFixtureReady(t, dir)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrProcessQuiescence) {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("cancellation failed to drain the job")
	}
}

func TestProcessTreeOutputAndExitCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, stderr, code, err := runCommandTree(ctx, os.Args[0], "-test.run=^TestProcessTreeHelper$", "--", "--tree-helper", "exit", t.TempDir())
	if out != "out\n" || stderr != "err\n" || code != 7 || err == nil {
		t.Fatalf("out=%q stderr=%q code=%d err=%v", out, stderr, code, err)
	}
}
