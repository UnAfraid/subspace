package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func RandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)[:n]
}

func Overwrite(filename string, data []byte, perm os.FileMode) error {
	f, err := ioutil.TempFile(filepath.Dir(filename), filepath.Base(filename)+".tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(f.Name(), perm); err != nil {
		return err
	}
	return os.Rename(f.Name(), filename)
}

func bash(tmpl string, params interface{}) (string, error) {
	t, err := shellTemplate(tmpl)
	if err != nil {
		return "", err
	}

	var script bytes.Buffer
	err = t.Execute(&script, params)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	logrus.Debugf("Executing: %s params: %+v", strings.ReplaceAll(string(script.Bytes()), "\\n", "\n"), params)

	output, err := exec.CommandContext(ctx, "/bin/bash", "-c", string(script.Bytes())).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command failed: %s\n%s", err, string(output))
	}
	return string(output), nil
}
