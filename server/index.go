/*
 * Copyright (C) 2024, 2025. Genome Research Ltd. All rights reserved.
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
	"sync"

	"github.com/cyverse/go-irodsclient/irods/types"
)

// ItemIndex is a collection of iRODS paths that have been tagged for presentation on
// the Sqyrrl web interface.
//
// The index is updated by the server as new items are added to the system. Each item
// has a category, which is used to group items together. The functions associated with
// the index allow the web interface to display the items in a structured way.
type ItemIndex struct {
	sync.RWMutex
	items []Item
}

// Item represents an indexed iRODS path.
type Item struct {
	Path     string // The iRODS path of the item.
	Size     int64  // The size of the item in bytes.
	Metadata []*types.IRODSMeta
	ACL      []*types.IRODSAccess
}

var defaultMetaFilter = func(avu types.IRODSMeta) bool {
	ignoreAttrs := []string{AccessTimeAttr, CategoryAttr, DublinCoreCreated, IndexAttr}
	for _, attr := range ignoreAttrs {
		if avu.Name == attr {
			return true
		}
	}
	return false
}

var defaultACLFilter = func(ac types.IRODSAccess) bool {
	ignoreUsers := []string{"irods", "irods-g1", "rodsBoot"}
	for _, user := range ignoreUsers {
		if ac.UserName == user {
			return true
		}
	}
	return false
}

// NewItemIndex creates a new item index with the given items.
func NewItemIndex(items []Item) *ItemIndex {
	return &ItemIndex{items: items}
}

// SetItems sets the items in the index, replacing the existing items.
func (index *ItemIndex) SetItems(items []Item) {
	index.Lock()
	defer index.Unlock()

	index.items = items
}

// Categories returns a sorted list of all the categories in the index.
func (index *ItemIndex) Categories() []string {
	index.RLock()
	defer index.RUnlock()

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
	index.RLock()
	defer index.RUnlock()

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
	index.RLock()
	defer index.RUnlock()

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

// Category returns the category of the item, which is an arbitrary string that can be
// used to group items together. The category value is extracted from the metadata of
// the path in iRODS, so to change categories, the iRODS metadata must be updated.
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

// SizeString returns a human-readable string representing the size of the in iRODS.
func (item *Item) SizeString() string {
	size := float64(item.Size)
	kib := float64(1024)
	mib := 1024 * kib
	gib := 1024 * mib

	switch {
	case size < kib:
		return fmt.Sprintf("%.0f B", size)
	case size < mib:
		return fmt.Sprintf("%.2f KiB", size/kib)
	case size < gib:
		return fmt.Sprintf("%.2f MiB", size/mib)
	default:
		return fmt.Sprintf("%.2f GiB", size/gib)
	}
}

// MetadataStrings returns a sorted list of strings representing the metadata of the item.
// The metadata are filtered by the given functions, which are applied to each metadata
// item. If a function returns true, the metadata item is excluded from the result.
func (item *Item) MetadataStrings(filter ...func(types.IRODSMeta) bool) []string {
	meta := make([]string, 0, len(item.Metadata))

	for _, avu := range item.Metadata {
		excluded := false
		for _, f := range filter {
			if f(*avu) {
				excluded = true
				break
			}
		}
		if !excluded {
			meta = append(meta, fmt.Sprintf("%s=%s", avu.Name, avu.Value))
		}
	}
	slices.Sort(meta)

	return meta
}

// ACLStrings returns a sorted list of strings representing the ACL of the item. The ACL
// is filtered by the given functions, which are applied to each access item. If a 
// function returns true, the access item is excluded from the result.
func (item *Item) ACLStrings(filter ...func(types.IRODSAccess) bool) []string {
	acl := make([]string, 0, len(item.ACL))

	for _, ac := range item.ACL {
		excluded := false
		for _, f := range filter {
			if f(*ac) {
				excluded = true
				break
			}
		}
		if !excluded {
			acl = append(acl, fmt.Sprintf("%s#%s:%s", ac.UserName, ac.UserZone, ac.AccessLevel))
		}
	}
	slices.Sort(acl)

	return acl
}

// FilteredMetadataStrings returns a sorted list of strings representing the metadata of
// the item, filtered by the default filter function.
func (item *Item) FilteredMetadataStrings() []string {
	s := item.MetadataStrings(defaultMetaFilter)
	if len(s) == 0 {
		return []string{"No relevant metadata to report"}
	}
	return s
}

// FilteredACLStrings returns a sorted list of strings representing the ACL of the item,
// filtered by the default filter function.
func (item *Item) FilteredACLStrings() []string {
	s := item.ACLStrings(defaultACLFilter)
	if len(s) == 0 {
		return []string{"No relevant ACLs to report"}
	}
	return s
}

// String returns a string representation of the item, including its path, category,
// size, ACL, and metadata. The ACL and metadata are filtered to remove uninformative
// entries.
func (item *Item) String() string {
	return fmt.Sprintf("<Item path='%s' category='%s' size:%d acl:[%s] metadata:[%s]>",
		item.Path,
		item.Category(),
		item.Size,
		strings.Join(item.ACLStrings(), ","),
		strings.Join(item.MetadataStrings(), ","))
}
