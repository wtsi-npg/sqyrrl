/*
 * Copyright (C) 2026. Genome Research Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package server

import (
	"fmt"
	"net/url"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/cyverse/go-irodsclient/irods/types"
)

type BrowseEntry struct {
	Path         string
	Name         string
	Size         int64
	IsCollection bool
	Metadata     []*types.IRODSMeta
	ACL          []*types.IRODSAccess
	Link         string
}

func (entry BrowseEntry) DisplayName() string {
	if entry.IsCollection {
		return entry.Name + "/"
	}

	return entry.Name
}

func (entry BrowseEntry) SizeString() string {
	if entry.IsCollection {
		return ""
	}

	number, unit := sizeParts(entry.Size)
	return fmt.Sprintf("%s %s", number, unit)
}

func (entry BrowseEntry) SizeNumber() string {
	if entry.IsCollection {
		return ""
	}

	number, _ := sizeParts(entry.Size)
	return number
}

func (entry BrowseEntry) SizeUnit() string {
	if entry.IsCollection {
		return ""
	}

	_, unit := sizeParts(entry.Size)
	return unit
}

func (entry BrowseEntry) FilteredMetadataStrings() []string {
	meta := make([]string, 0, len(entry.Metadata))
	for _, avu := range entry.Metadata {
		if !defaultMetaFilter(*avu) {
			meta = append(meta, fmt.Sprintf("%s=%s", avu.Name, avu.Value))
		}
	}

	slices.Sort(meta)
	if len(meta) == 0 {
		return []string{}
	}

	return meta
}

func (entry BrowseEntry) FilteredACLStrings() []string {
	acl := make([]string, 0, len(entry.ACL))
	for _, ac := range entry.ACL {
		if !defaultACLFilter(*ac) {
			acl = append(acl, fmt.Sprintf("%s#%s:%s", ac.UserName, ac.UserZone, ac.AccessLevel))
		}
	}

	slices.Sort(acl)

	return acl
}

type Breadcrumb struct {
	Name string
	Link string
}

func buildBreadcrumbs(rodsPath string) []Breadcrumb {
	cleaned := path.Clean(rodsPath)
	trimmed := strings.TrimPrefix(cleaned, "/")
	if trimmed == "" || trimmed == "." {
		return nil
	}

	parts := strings.Split(trimmed, "/")
	crumbs := make([]Breadcrumb, 0, len(parts))
	current := ""
	for _, part := range parts {
		current = path.Join(current, part)
		crumbs = append(crumbs, Breadcrumb{
			Name: part,
			Link: buildEscapedPath(EndpointBrowse, current),
		})
	}

	return crumbs
}

func buildBrowseURL(rodsPath string) string {
	return buildEscapedPath(EndpointBrowse, rodsPath)
}

func buildIRODSURL(rodsPath string) string {
	return buildEscapedPath(EndpointIRODS, rodsPath)
}

func buildEscapedPath(prefix, rodsPath string) string {
	cleaned := path.Clean(rodsPath)
	trimmed := strings.TrimPrefix(cleaned, "/")
	if trimmed == "" || trimmed == "." {
		return prefix
	}

	parts := strings.Split(trimmed, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}

	escaped := path.Join(parts...)
	return path.Join(prefix, escaped)
}

func zoneRootPath(rodsPath string) string {
	cleaned := path.Clean(rodsPath)
	trimmed := strings.TrimPrefix(cleaned, "/")
	if trimmed == "" || trimmed == "." {
		return "/"
	}

	parts := strings.Split(trimmed, "/")
	return "/" + parts[0]
}

func sortBrowseEntries(entries []BrowseEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsCollection != entries[j].IsCollection {
			return entries[i].IsCollection
		}

		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
}
