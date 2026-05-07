/* SPDX-License-Identifier: MIT */

package turn

import "strings"

func normalizeVKJoinLink(link string) string {
	link = strings.TrimSpace(link)
	for _, marker := range []string{"join/", "call/"} {
		if parts := strings.Split(link, marker); len(parts) > 1 {
			link = parts[len(parts)-1]
			break
		}
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}
	return link
}
