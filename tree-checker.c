/*
 * Copyright (C) Qu Wenruo 2017.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program.
 */

/*
 * The module is used to catch unexpected/corrupted tree block data.
 * Such behavior can be caused either by a fuzzed image or bugs.
 *
 * The objective is to do leaf/node validation checks when tree block is read
 * from disk, and check *every* possible member, so other code won't
 * need to checking them again.
 *
 * Due to the potential and unwanted damage, every checker needs to be
 * carefully reviewed otherwise so it does not prevent mount of valid images.
 */

#include <stdarg.h>
#include <uuid/uuid.h>
#include "ctree.h"
#include "tree-checker.h"
#include "disk-io.h"
#include "messages.h"
#include "common-defs.h"
#include "extent_io.h"
#include "volumes.h"
//#include "compression.h"

/* specified errno for check_tree_block */
#define BTRFS_BAD_BYTENR		(-1)
#define BTRFS_BAD_FSID			(-2)
#define BTRFS_BAD_LEVEL			(-3)
#define BTRFS_BAD_NRITEMS		(-4)

/* Calculate max possible nritems for a leaf/node */
static u32 max_nritems(u8 level, u32 nodesize)
{

	if (level == 0)
		return ((nodesize - sizeof(struct btrfs_header)) /
			sizeof(struct btrfs_item));
	return ((nodesize - sizeof(struct btrfs_header)) /
		sizeof(struct btrfs_key_ptr));
}

/*
 * Error message should follow the following format:
 * corrupt <type>: <identifier>, <reason>[, <bad_value>]
 *
 * @type:	leaf or node
 * @identifier:	the necessary info to locate the leaf/node.
 * 		It's recommened to decode key.objecitd/offset if it's
 * 		meaningful.
 * @reason:	describe the error
 * @bad_value:	optional, it's recommened to output bad value and its
 *		expected value (range).
 *
 * Since comma is used to separate the components, only space is allowed
 * inside each component.
 */

/*
 * Append generic "corrupt leaf/node root=%llu block=%llu slot=%d: " to @fmt.
 * Allows callers to customize the output.
 * When r_objectid is 0, this means does not know which is the root of
 * this eb.
 */
#define FORM_SIZE 100
static char form[FORM_SIZE];
#define generic_err(fs_info, r_objectid, eb, slot, fmt, ...)		\
{									\
	if (!fs_info->suppress_check_block_errors) {			\
		memset(form, 0, FORM_SIZE);				\
		sprintf(form,						\
			"corrupt %s: root=%llu block=%llu slot=%d, ",	\
			btrfs_header_level(eb) == 0 ? "leaf" : "node",	\
			r_objectid, btrfs_header_bytenr(eb), slot);	\
		strncpy(form + strlen(form), fmt, sizeof(fmt));		\
		__btrfs_warning((form), ##__VA_ARGS__);			\
	}								\
}

/*
 * Customized reporter for extent data item, since its key objectid and
 * offset has its own meaning.
 * When r_objectid is 0, this means does not know which is the root of
 * this eb.
 */
#define file_extent_err(fs_info, r_objectid, eb, slot, fmt, ...)	\
{									\
	if (!fs_info->suppress_check_block_errors) {			\
		struct btrfs_key key_tmp;				\
		btrfs_item_key_to_cpu(eb, &key_tmp, slot);		\
		memset(form, 0, FORM_SIZE);				\
		sprintf(form,						\
"corrupt %s: root=%llu block=%llu slot=%d ino=%llu file_offset=%llu, ",	\
			btrfs_header_level(eb) == 0 ? "leaf" : "node",	\
			r_objectid, btrfs_header_bytenr(eb), slot,	\
			key_tmp.objectid, key_tmp.offset);		\
		strncpy(form + strlen(form), fmt, sizeof(fmt));		\
		__btrfs_warning((form), ##__VA_ARGS__);			\
	}								\
}

/*
 * Return 0 if the btrfs_file_extent_##name is aligned to @alignment
 * Else return 1
 */
#define CHECK_FE_ALIGNED(fs_info, r_objectid, leaf, slot, fi, name, alignment) \
({									      \
	if (!IS_ALIGNED(btrfs_file_extent_##name((leaf), (fi)), (alignment))) \
		file_extent_err((fs_info), (r_objectid), (leaf), (slot),		      \
	"invalid %s for file extent, have %llu, should be aligned to %u",     \
			(#name), btrfs_file_extent_##name((leaf), (fi)),      \
			(alignment));					      \
	(!IS_ALIGNED(btrfs_file_extent_##name((leaf), (fi)), (alignment)));   \
})

static int check_extent_data_item(struct btrfs_fs_info *fs_info,
				  u64 r_objectid,
				  struct extent_buffer *leaf,
				  struct btrfs_key *key, int slot)
{
	struct btrfs_file_extent_item *fi;
	u32 sectorsize = fs_info->sectorsize;
	u32 item_size = btrfs_item_size_nr(leaf, slot);

	if (!IS_ALIGNED(key->offset, sectorsize)) {
		file_extent_err(fs_info, r_objectid, leaf, slot,
"unaligned file_offset for file extent, have %llu should be aligned to %u",
			key->offset, sectorsize);
		return -EUCLEAN;
	}

	fi = btrfs_item_ptr(leaf, slot, struct btrfs_file_extent_item);

	if (btrfs_file_extent_type(leaf, fi) > BTRFS_FILE_EXTENT_TYPES) {
		file_extent_err(fs_info, r_objectid, leaf, slot,
		"invalid type for file extent, have %u expect range [0, %u]",
			btrfs_file_extent_type(leaf, fi),
			BTRFS_FILE_EXTENT_TYPES);
		return -EUCLEAN;
	}

	/*
	 * Support for new compression/encrption must introduce incompat flag,
	 * and must be caught in open_ctree().
	 */
	if (btrfs_file_extent_compression(leaf, fi) > BTRFS_COMPRESS_TYPES) {
		file_extent_err(fs_info, r_objectid, leaf, slot,
	"invalid compression for file extent, have %u expect range [0, %u]",
			btrfs_file_extent_compression(leaf, fi),
			BTRFS_COMPRESS_TYPES);
		return -EUCLEAN;
	}
	if (btrfs_file_extent_encryption(leaf, fi)) {
		file_extent_err(fs_info, r_objectid, leaf, slot,
			"invalid encryption for file extent, have %u expect 0",
			btrfs_file_extent_encryption(leaf, fi));
		return -EUCLEAN;
	}
	if (btrfs_file_extent_type(leaf, fi) == BTRFS_FILE_EXTENT_INLINE) {
		/* Inline extent must have 0 as key offset */
		if (key->offset) {
			file_extent_err(fs_info, r_objectid, leaf, slot,
		"invalid file_offset for inline file extent, have %llu expect 0",
				key->offset);
			return -EUCLEAN;
		}

		/* Compressed inline extent has no on-disk size, skip it */
		if (btrfs_file_extent_compression(leaf, fi) !=
		    BTRFS_COMPRESS_NONE)
			return 0;

		/* Uncompressed inline extent size must match item size */
		if (item_size != BTRFS_FILE_EXTENT_INLINE_DATA_START +
		    btrfs_file_extent_ram_bytes(leaf, fi)) {
			file_extent_err(fs_info, r_objectid, leaf, slot,
	"invalid ram_bytes for uncompressed inline extent, have %u expect %llu",
				item_size, BTRFS_FILE_EXTENT_INLINE_DATA_START +
				btrfs_file_extent_ram_bytes(leaf, fi));
			return -EUCLEAN;
		}
		return 0;
	}

	/* Regular or preallocated extent has fixed item size */
	if (item_size != sizeof(*fi)) {
		file_extent_err(fs_info, r_objectid, leaf, slot,
	"invalid item size for reg/prealloc file extent, have %u expect %zu",
			item_size, sizeof(*fi));
		return -EUCLEAN;
	}
	if (CHECK_FE_ALIGNED(fs_info, r_objectid, leaf, slot, fi, ram_bytes, sectorsize) ||
	    CHECK_FE_ALIGNED(fs_info, r_objectid, leaf, slot, fi, disk_bytenr, sectorsize) ||
	    CHECK_FE_ALIGNED(fs_info, r_objectid, leaf, slot, fi, disk_num_bytes, sectorsize) ||
	    CHECK_FE_ALIGNED(fs_info, r_objectid, leaf, slot, fi, offset, sectorsize) ||
	    CHECK_FE_ALIGNED(fs_info, r_objectid, leaf, slot, fi, num_bytes, sectorsize))
		return -EUCLEAN;
	return 0;
}

static int check_csum_item(struct btrfs_fs_info *fs_info,
			   u64 r_objectid, struct extent_buffer *leaf,
			   struct btrfs_key *key, int slot)
{
	u32 sectorsize = fs_info->sectorsize;
	u32 csumsize = btrfs_super_csum_size(fs_info->super_copy);

	if (key->objectid != BTRFS_EXTENT_CSUM_OBJECTID) {
		generic_err(fs_info, r_objectid, leaf, slot,
		"invalid key objectid for csum item, have %llu expect %llu",
			key->objectid, BTRFS_EXTENT_CSUM_OBJECTID);
		return -EUCLEAN;
	}
	if (!IS_ALIGNED(key->offset, sectorsize)) {
		generic_err(fs_info, r_objectid, leaf, slot,
	"unaligned key offset for csum item, have %llu should be aligned to %u",
			key->offset, sectorsize);
		return -EUCLEAN;
	}
	if (!IS_ALIGNED(btrfs_item_size_nr(leaf, slot), csumsize)) {
		generic_err(fs_info, r_objectid, leaf, slot,
	"unaligned item size for csum item, have %u should be aligned to %u",
			btrfs_item_size_nr(leaf, slot), csumsize);
		return -EUCLEAN;
	}
	return 0;
}

/*
 * Common point to switch the item-specific validation.
 */
static int check_leaf_item(struct btrfs_fs_info *fs_info,
			   u64 r_objectid,
			   struct extent_buffer *leaf,
			   struct btrfs_key *key, int slot)
{
	int ret = 0;

	switch (key->type) {
	case BTRFS_EXTENT_DATA_KEY:
		ret = check_extent_data_item(fs_info, r_objectid,
				leaf, key, slot);
		break;
	case BTRFS_EXTENT_CSUM_KEY:
		ret = check_csum_item(fs_info, r_objectid, leaf, key, slot);
		break;
	}
	return ret;
}

static int check_leaf(struct btrfs_fs_info *fs_info, u64 r_objectid,
		      struct extent_buffer *leaf,
		      bool check_item_data)
{
	/* No valid key type is 0, so all key should be larger than this key */
	struct btrfs_key prev_key = {0, 0, 0};
	struct btrfs_key key;
	u32 nritems = btrfs_header_nritems(leaf);
	int slot;

	/*
	 * Extent buffers from a relocation tree have a owner field that
	 * corresponds to the subvolume tree they are based on. So just from an
	 * extent buffer alone we can not find out what is the id of the
	 * corresponding subvolume tree, so we can not figure out if the extent
	 * buffer corresponds to the root of the relocation tree or not. So
	 * skip this check for relocation trees.
	 */
	if (nritems == 0 && !btrfs_header_flag(leaf, BTRFS_HEADER_FLAG_RELOC)) {
		struct btrfs_root *check_root = NULL;

		key.objectid = btrfs_header_owner(leaf);
		key.type = BTRFS_ROOT_ITEM_KEY;
		key.offset = (u64)-1;

		//check_root = btrfs_get_fs_root(fs_info, &key, false);
		/*
		 * The only reason we also check NULL here is that during
		 * open_ctree() some roots has not yet been set up.
		 */
		if (!IS_ERR_OR_NULL(check_root)) {
			struct extent_buffer *eb;

			eb = btrfs_root_node(check_root);
			/* if leaf is the root, then it's fine */
			if (leaf != eb) {
				generic_err(fs_info, check_root->objectid,
					leaf, 0,
		"invalid nritems, have %u should not be 0 for non-root leaf",
					nritems);
				free_extent_buffer(eb);
				return -EUCLEAN;
			}
			free_extent_buffer(eb);
		}
		return 0;
	}

	if (nritems == 0)
		return 0;

	/*
	 * Check the following things to make sure this is a good leaf, and
	 * leaf users won't need to bother with similar sanity checks:
	 *
	 * 1) key ordering
	 * 2) item offset and size
	 *    No overlap, no hole, all inside the leaf.
	 * 3) item content
	 *    If possible, do comprehensive sanity check.
	 *    NOTE: All checks must only rely on the item data itself.
	 */
	for (slot = 0; slot < nritems; slot++) {
		u32 item_end_expected;
		int ret;

		btrfs_item_key_to_cpu(leaf, &key, slot);

		/* Make sure the keys are in the right order */
		if (btrfs_comp_cpu_keys(&prev_key, &key) >= 0) {
			generic_err(fs_info, r_objectid, leaf, slot,
	"bad key order, prev (%llu %u %llu) current (%llu %u %llu)",
				prev_key.objectid, prev_key.type,
				prev_key.offset, key.objectid, key.type,
				key.offset);
			return -EUCLEAN;
		}

		/*
		 * Make sure the offset and ends are right, remember that the
		 * item data starts at the end of the leaf and grows towards the
		 * front.
		 */
		if (slot == 0)
			item_end_expected = 0;//item_end_expected = BTRFS_LEAF_DATA_SIZE(root);
		else
			item_end_expected = btrfs_item_offset_nr(leaf,
								 slot - 1);
		if (btrfs_item_end_nr(leaf, slot) != item_end_expected) {
			generic_err(fs_info, r_objectid, leaf, slot,
				"unexpected item end, have %u expect %u",
				btrfs_item_end_nr(leaf, slot),
				item_end_expected);
			return -EUCLEAN;
		}

		/*
		 * Check to make sure that we don't point outside of the leaf,
		 * just in case all the items are consistent to each other, but
		 * all point outside of the leaf.
		 */
		if (btrfs_item_end_nr(leaf, slot) > 0) {
//		    BTRFS_LEAF_DATA_SIZE(root)) {
			generic_err(fs_info, r_objectid, leaf, slot,
			"slot end outside of leaf, have %u expect range [0, %u]",
				btrfs_item_end_nr(leaf, slot),0);
				//BTRFS_LEAF_DATA_SIZE(root));
			return -EUCLEAN;
		}

		/* Also check if the item pointer overlaps with btrfs item. */
		if (btrfs_item_nr_offset(slot) + sizeof(struct btrfs_item) >
		    btrfs_item_ptr_offset(leaf, slot)) {
			generic_err(fs_info, r_objectid, leaf, slot,
		"slot overlaps with its data, item end %lu data start %lu",
				btrfs_item_nr_offset(slot) +
				sizeof(struct btrfs_item),
				btrfs_item_ptr_offset(leaf, slot));
			return -EUCLEAN;
		}

		if (check_item_data) {
			/*
			 * Check if the item size and content meet other
			 * criteria
			 */
			ret = check_leaf_item(fs_info, r_objectid, leaf, &key, slot);
			if (ret < 0)
				return ret;
		}

		prev_key.objectid = key.objectid;
		prev_key.type = key.type;
		prev_key.offset = key.offset;
	}

	return 0;
}

static void print_tree_block_error(struct btrfs_fs_info *fs_info,
				struct extent_buffer *eb,
				int err)
{
	char fs_uuid[BTRFS_UUID_UNPARSED_SIZE] = {'\0'};
	char found_uuid[BTRFS_UUID_UNPARSED_SIZE] = {'\0'};
	u8 buf[BTRFS_UUID_SIZE];

	switch (err) {
	case BTRFS_BAD_FSID:
		read_extent_buffer(eb, buf, btrfs_header_fsid(),
				   BTRFS_UUID_SIZE);
		uuid_unparse(buf, found_uuid);
		uuid_unparse(fs_info->fsid, fs_uuid);
		fprintf(stderr, "fsid mismatch, want=%s, have=%s\n",
			fs_uuid, found_uuid);
		break;
	case BTRFS_BAD_BYTENR:
		fprintf(stderr, "bytenr mismatch, want=%llu, have=%llu\n",
			eb->start, btrfs_header_bytenr(eb));
		break;
	case BTRFS_BAD_LEVEL:
		fprintf(stderr, "bad level, %u > %u\n",
			btrfs_header_level(eb), BTRFS_MAX_LEVEL);
		break;
	case BTRFS_BAD_NRITEMS:
		fprintf(stderr, "invalid nr_items: %u\n",
			btrfs_header_nritems(eb));
		break;
	}
}
int btrfs_check_tree_block_common(struct btrfs_fs_info *fs_info,
				u64 r_objectid, struct extent_buffer *buf)
{

	struct btrfs_fs_devices *fs_devices;
	u32 nodesize = fs_info->nodesize;
	int ret = BTRFS_BAD_FSID;

	if (buf->start != btrfs_header_bytenr(buf)) {
		ret = BTRFS_BAD_BYTENR;
		goto out;
	}
	if (btrfs_header_level(buf) >= BTRFS_MAX_LEVEL) {
		ret = BTRFS_BAD_LEVEL;
		goto out;
	}
	if (btrfs_header_nritems(buf) > max_nritems(btrfs_header_level(buf),
						    nodesize)) {
		ret = BTRFS_BAD_NRITEMS;
		goto out;
	}

	/* Only leaf can be empty */
	if (btrfs_header_nritems(buf) == 0 &&
	    btrfs_header_level(buf) != 0)
		ret = BTRFS_BAD_NRITEMS;

	fs_devices = fs_info->fs_devices;
	while (fs_devices) {
		if (fs_info->ignore_fsid_mismatch ||
		    !memcmp_extent_buffer(buf, fs_devices->fsid,
					  btrfs_header_fsid(),
					  BTRFS_FSID_SIZE)) {
			ret = 0;
			break;
		}
		fs_devices = fs_devices->seed;
	}
out:
	if (ret !=0 && !fs_info->suppress_check_block_errors)
		print_tree_block_error(fs_info, buf, ret);
	return ret;
}

int btrfs_check_leaf_full(struct btrfs_fs_info *fs_info, u64 r_objectid,
			  struct extent_buffer *leaf)
{
	return check_leaf(fs_info, r_objectid, leaf, true);
}

int btrfs_check_leaf_relaxed(struct btrfs_fs_info *fs_info, u64 r_objectid,
			     struct extent_buffer *leaf)
{
	return check_leaf(fs_info, r_objectid, leaf, false);
}

int btrfs_check_node(struct btrfs_fs_info *fs_info, u64 r_objectid,
		     struct extent_buffer *node)
{
	unsigned long nr = btrfs_header_nritems(node);
	struct btrfs_key key, next_key;
	int slot;
	u64 bytenr;
	int ret = 0;

	if (nr == 0 || nr > 0) {
			//BTRFS_NODEPTRS_PER_BLOCK(root)) {
		if (!fs_info->suppress_check_block_errors)
			warning(
	"corrupt node: root=%llu block=%llu, nritems too %s, have %lu expect range [1,%u]",
				r_objectid, node->start,
				nr == 0 ? "small" : "large", nr,
				0);//BTRFS_NODEPTRS_PER_BLOCK(root));
		return -EUCLEAN;
	}

	for (slot = 0; slot < nr - 1; slot++) {
		bytenr = btrfs_node_blockptr(node, slot);
		btrfs_node_key_to_cpu(node, &key, slot);
		btrfs_node_key_to_cpu(node, &next_key, slot + 1);

		if (!bytenr) {
			generic_err(fs_info, r_objectid, node, slot,
				"invalid NULL node pointer");
			ret = -EUCLEAN;
			goto out;
		}
		if (!IS_ALIGNED(bytenr, fs_info->sectorsize)) {
			generic_err(fs_info, r_objectid, node, slot,
			"unaligned pointer, have %llu should be aligned to %u",
				bytenr, fs_info->sectorsize);
			ret = -EUCLEAN;
			goto out;
		}

		if (btrfs_comp_cpu_keys(&key, &next_key) >= 0) {
			generic_err(fs_info, r_objectid, node, slot,
	"bad key order, current (%llu %u %llu) next (%llu %u %llu)",
				key.objectid, key.type, key.offset,
				next_key.objectid, next_key.type,
				next_key.offset);
			ret = -EUCLEAN;
			goto out;
		}
	}
out:
	return ret;
}

int btrfs_check_tree_block(struct btrfs_fs_info *fs_info, u64 r_objectid,
		struct extent_buffer *eb)
{
	int ret;
	ret = btrfs_check_tree_block_common(fs_info, r_objectid, eb);
	if (ret != 0)
		goto out;
	if (btrfs_header_level(eb) == 0) {
		ret = btrfs_check_leaf_full(fs_info, r_objectid, eb);
	} else {
		ret = btrfs_check_node(fs_info, r_objectid, eb);
	}
out:
	return ret;
}
