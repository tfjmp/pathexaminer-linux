/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2015-2018 University of Cambridge, Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef _PROVENANCE_RECORD_H
#define _PROVENANCE_RECORD_H

#include "provenance.h"
#include "provenance_relay.h"

static inline int record_node_name(struct provenance *node, const char *name)
{
	union long_prov_elt *fname_prov;
	int rc;

	if (provenance_is_name_recorded(prov_elt(node)) || !provenance_is_recorded(prov_elt(node)))
		return 0;

	fname_prov = alloc_long_provenance(ENT_FILE_NAME);
	if (!fname_prov)
		return -ENOMEM;

	strlcpy(fname_prov->file_name_info.name, name, PATH_MAX);
	fname_prov->file_name_info.length = strnlen(fname_prov->file_name_info.name, PATH_MAX);

	// record the relation
	spin_lock(prov_lock(node));
	if (prov_type(prov_elt(node)) == ACT_TASK) {
		rc = write_relation(RL_NAMED_PROCESS, fname_prov, prov_elt(node), NULL, 0);
		set_name_recorded(prov_elt(node));
	} else{
		rc = write_relation(RL_NAMED, fname_prov, prov_elt(node), NULL, 0);
		set_name_recorded(prov_elt(node));
	}
	spin_unlock(prov_lock(node));
	free_long_provenance(fname_prov);
	return rc;
}

static inline int record_log(union prov_elt *cprov, const char __user *buf, size_t count)
{
	union long_prov_elt *str;
	int rc = 0;

	str = alloc_long_provenance(ENT_STR);
	if (!str) {
		rc = -ENOMEM;
		goto out;
	}
	if (copy_from_user(str->str_info.str, buf, count)) {
		rc = -EAGAIN;
		goto out;
	}
	str->str_info.str[count] = '\0'; // make sure the string is null terminated
	str->str_info.length = count;

	rc = write_relation(RL_LOG, str, cprov, NULL, 0);
out:
	free_long_provenance(str);
	if (rc < 0)
		return rc;
	return count;
}

static __always_inline int __update_version(const uint64_t type, struct provenance *prov)
{
	union prov_elt old_prov;
	int rc = 0;

	// there is no outgoing edge and we are compressing
	if (!prov->has_outgoing && prov_policy.should_compress_node)
		return 0;
	// is it an edge type that needs update
	if (filter_update_node(type))
		return 0;
	// copy provenance to old
	memcpy(&old_prov, prov_elt(prov), sizeof(old_prov));
	// update version
	node_identifier(prov_elt(prov)).version++;
	clear_recorded(prov_elt(prov));

	// record version relation between version
	if (node_identifier(prov_elt(prov)).type == ACT_TASK)
		rc = write_relation(RL_VERSION_TASK, &old_prov, prov_elt(prov), NULL, 0);
	else
		rc = write_relation(RL_VERSION, &old_prov, prov_elt(prov), NULL, 0);
	prov->has_outgoing = false;     // we update there is no more outgoing edge
	prov->saved = false;            // for inode prov persistance
	return rc;
}

static __always_inline int record_relation(const uint64_t type,
				  struct provenance *from,
				  struct provenance *to,
				  const struct file *file,
				  const uint64_t flags)
{
	int rc = 0;

	if (prov_policy.should_compress_edge) {
		// we compress edges, do not record same edge type twice
		if (to->previous_id == node_identifier(prov_entry(from)).id
		    && to->previous_type == type)
			return 0;
		else {   // if not we save those information
			to->previous_id = node_identifier(prov_entry(from)).id;
			to->previous_type = type;
		}
	}

	rc = __update_version(type, to);
	if (rc < 0)
		return rc;
	from->has_outgoing = true; // there is an outgoing edge
	rc = write_relation(type, prov_elt(from), prov_elt(to), file, flags);
	return rc;
}

static __always_inline int current_update_shst(struct provenance *cprov, bool read);

// from (entity) to (activity)
static __always_inline int uses(const uint64_t type,
				struct provenance *from,
				struct provenance *tprov,
				struct provenance *cprov,
				const struct file *file,
				const uint64_t flags)
{
	int rc;

	BUILD_BUG_ON(!prov_is_used(type));

	// check if the nodes match some capture options
	apply_target(prov_elt(from));
	apply_target(prov_elt(tprov));
	apply_target(prov_elt(cprov));

	if (!provenance_is_tracked(prov_elt(from))
	    && !provenance_is_tracked(prov_elt(tprov))
	    && !provenance_is_tracked(prov_elt(cprov))
	    && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(type, prov_entry(from), prov_entry(tprov)))
		return 0;

	rc = record_relation(type, from, tprov, file, flags);
	if (rc < 0)
		goto out;
	rc = record_relation(RL_PROC_WRITE, tprov, cprov, NULL, 0);
	if (rc < 0)
		goto out;
	rc = current_update_shst(cprov, false);
out:
	return rc;
}

// from (entity) to (activity)
static __always_inline int uses_two(const uint64_t type,
				struct provenance *from,
				struct provenance *to,
				const struct file *file,
				const uint64_t flags)
{
	BUILD_BUG_ON(!prov_is_used(type));

	// check if the nodes match some capture options
	apply_target(prov_elt(from));
	apply_target(prov_elt(to));

	if (!provenance_is_tracked(prov_elt(from))
	    && !provenance_is_tracked(prov_elt(to))
	    && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(type, prov_entry(from), prov_entry(to)))
		return 0;
	return record_relation(type, from, to, file, flags);
}

// from (activity) to (entity)
static __always_inline int generates(const uint64_t type,
				     struct provenance *cprov,
				     struct provenance *tprov,
				     struct provenance *to,
				     const struct file *file,
				     const uint64_t flags)
{
	int rc;

	BUILD_BUG_ON(!prov_is_generated(type));

	// check if the nodes match some capture options
	apply_target(prov_elt(cprov));
	apply_target(prov_elt(tprov));
	apply_target(prov_elt(to));

	if (!provenance_is_tracked(prov_elt(cprov))
	    && !provenance_is_tracked(prov_elt(tprov))
	    && !provenance_is_tracked(prov_elt(to))
	    && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(type, prov_entry(tprov), prov_entry(to)))
		return 0;

	rc = current_update_shst(cprov, true);
	if (rc < 0)
		goto out;
	rc = record_relation(RL_PROC_READ, cprov, tprov, NULL, 0);
	if (rc < 0)
		goto out;
	rc = record_relation(type, tprov, to, file, flags);
out:
	return rc;
}

// from (entity) to (entity)
static __always_inline int derives(const uint64_t type,
				   struct provenance *from,
				   struct provenance *to,
				   const struct file *file,
				   const uint64_t flags)
{
	BUILD_BUG_ON(!prov_is_derived(type));

	// check if the nodes match some capture options
	apply_target(prov_elt(from));
	apply_target(prov_elt(to));

	if (!provenance_is_tracked(prov_elt(from))
	    && !provenance_is_tracked(prov_elt(to))
	    && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(type, prov_entry(from), prov_entry(to)))
		return 0;

	return record_relation(type, from, to, file, flags);
}

// from (activity) to (activity)
static __always_inline int informs(const uint64_t type,
				   struct provenance *from,
				   struct provenance *to,
				   const struct file *file,
				   const uint64_t flags)
{
	BUILD_BUG_ON(!prov_is_informed(type));

	// check if the nodes match some capture options
	apply_target(prov_elt(from));
	apply_target(prov_elt(to));

	if (!provenance_is_tracked(prov_elt(from))
	    && !provenance_is_tracked(prov_elt(to))
	    && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(type, prov_entry(from), prov_entry(to)))
		return 0;

	return record_relation(type, from, to, file, flags);
}
#endif
