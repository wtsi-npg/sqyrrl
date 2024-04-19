/*
 * Copyright (C) 2024. Genome Research Ltd. All rights reserved.
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
	"slices"
	"sort"
	"strings"

	"github.com/cyverse/go-irodsclient/irods/types"
)

// ItemIndex is a collection of iRODS paths that have been tagged for presentation on
// the Sqyrrl web interface.
//
// The index is updated by the server as new items are added to the system. Each item
// has a category, which is used to group items together. The functions associated with
// the index allow the web interface to display the items in a structured way.
type ItemIndex struct {
	items []Item
}

// Item represents a item in the index.
type Item struct {
	Path     string // The iRODS path of the item.
	Size     int64  // The size of the item in bytes.
	Metadata []*types.IRODSMeta
	ACL      []*types.IRODSAccess
}

func NewItemIndex(items []Item) *ItemIndex {
	return &ItemIndex{items: items}
}

// Categories returns a sorted list of all the categories in the index.
func (index *ItemIndex) Categories() []string {
	var categorySet = make(map[string]struct{})
	for _, item := range index.items {
		categorySet[item.Category()] = struct{}{}
	}

	categories := make([]string, len(categorySet))
	i := 0
	for cat := range categorySet {
		categories[i] = cat
		i++
	}
	slices.Sort(categories)

	return categories
}

// ItemsInCategory returns a sorted list of all the items in the index that are in the
// given category.
func (index *ItemIndex) ItemsInCategory(cat string) []Item {
	var items []Item
	for _, item := range index.items {
		if item.Category() == cat {
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Path < items[j].Path
	})

	return items
}

func (index *ItemIndex) String() string {
	var sb strings.Builder
	sb.WriteString("<ItemIndex")

	for _, cat := range index.Categories() {
		sb.WriteString(" ")
		sb.WriteString(cat)
		sb.WriteString(": ")

		items := index.ItemsInCategory(cat)
		for i, item := range items {
			sb.WriteString(item.String())
			if i < len(items)-1 {
				sb.WriteString(", ")
			}
		}
	}
	sb.WriteString(">")

	return sb.String()
}

func (item *Item) Category() string {
	var category string
	for _, meta := range item.Metadata {
		if meta.Name == CategoryAttr {
			category = meta.Value
			break
		}
	}
	return category
}

func (item *Item) SizeString() string {
	if item.Size < 1024 {
		return fmt.Sprintf("%d B", item.Size)
	}

	return fmt.Sprintf("%d KiB", item.Size/1024)
}

// MetadataStrings returns a sorted list of strings representing the metadata of the item.
func (item *Item) MetadataStrings() []string {
	var meta []string
	for _, m := range item.Metadata {
		meta = append(meta, fmt.Sprintf("%s=%s", m.Name, m.Value))
	}
	slices.Sort(meta)

	return meta
}

// ACLStrings returns a sorted list of strings representing the ACL of the item.
func (item *Item) ACLStrings() []string {
	var acl []string
	for _, a := range item.ACL {
		acl = append(acl, fmt.Sprintf("%s#%s:%s", a.UserName, a.UserZone, a.AccessLevel))
	}
	slices.Sort(acl)

	return acl
}

func (item *Item) String() string {
	return fmt.Sprintf("<Item path='%s' category='%s' size:%d acl:[%s] metadata:[%s]>",
		item.Path,
		item.Category(),
		item.Size,
		strings.Join(item.ACLStrings(), ", "),
		strings.Join(item.MetadataStrings(), ", "))
}
