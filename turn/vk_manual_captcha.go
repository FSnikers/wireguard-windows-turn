/* SPDX-License-Identifier: MIT */

package turn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func solveVkCaptchaManual(ctx context.Context, redirectURI, command string) (string, error) {
	if redirectURI == "" {
		return "", fmt.Errorf("manual VK captcha requires redirect URI")
	}
	if strings.TrimSpace(command) == "" {
		turnLog("[Captcha] Manual VK captcha URL: %s", redirectURI)
		return "", fmt.Errorf("VKCaptchaCommand is required when manual VK captcha solving is enabled")
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	command = strings.ReplaceAll(command, "{url}", redirectURI)
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(cmdCtx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(cmdCtx, "sh", "-c", command)
	}
	cmd.Env = append(os.Environ(), "VK_CAPTCHA_URL="+redirectURI)

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("manual VK captcha command failed: %w", err)
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", fmt.Errorf("manual VK captcha command returned an empty success_token")
	}
	return token, nil
}
