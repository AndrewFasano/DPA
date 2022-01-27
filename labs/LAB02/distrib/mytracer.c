#include <stddef.h>
#include <dr_api.h>
#include <drsyms.h>
#include <string.h>

#define MAX_NUM_MODULES 256

static void event_exit(void);
static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating);
static void event_module_load(void *drcontext, const module_data_t *info, bool loaded);
static void event_module_unload(void *drcontext, const module_data_t *info);
static int global_count;

typedef struct _module_array_t {
	unsigned long base;
	unsigned long end;
	unsigned int count;
	size_t size;
	bool   loaded;
	module_data_t *info;
	byte* bitmap;
} module_array_t;

static module_array_t mod_array[MAX_NUM_MODULES];
static int mod_count = 0;
static void *mod_lock;

DR_EXPORT void dr_init(client_id_t id) {
	mod_lock = dr_mutex_create();
	dr_register_exit_event(event_exit);
	dr_register_bb_event(event_basic_block);
	dr_register_module_load_event(event_module_load);
	dr_register_module_unload_event(event_module_unload);
	dr_log(NULL, DR_LOG_ALL, 1, "Client 'bbhit' initializing\n");	
}

static drsym_info_t* create_drsym_info() {
	drsym_info_t* info;
	info = malloc(sizeof(drsym_info_t));
	info->struct_size = sizeof(drsym_info_t);
	info->debug_kind = DRSYM_SYMBOLS;	
	info->name_size = 256;
	info->file_size = 256;
	info->file=malloc(256);
	info->name=malloc(256);
	return info;
}

static void free_drsmy_info(drsym_info_t * info) {
	if (info->file != NULL) 
		free(info->file);
	if (info->name != NULL) 
		free(info->name);
	free(info);
}

static void event_exit(void) {
  	dr_fprintf(STDERR, "info: EXIT");
	int i,j;
	drsym_init(0);
	drsym_info_t* syminfo = create_drsym_info();
	drsym_error_t err;
	dr_mutex_lock(mod_lock);
	dr_printf("\n===\nModules:\n");
	for (i = 0; i < mod_count; i++) {
		syminfo->start_offs = 0;
		syminfo->end_offs = 0;
		dr_printf("\t- [%c] (%8d) %s [%s]\n", (mod_array[i].loaded ? '+':'-'), mod_array[i].count, dr_module_preferred_name(mod_array[i].info) , mod_array[i].info->full_path);
		if (mod_array[i].bitmap != NULL) {
			for(j=0; j < mod_array[i].size; j++) {
				if (mod_array[i].bitmap[j] != 0) {
					int old = (syminfo->start_offs <= j && syminfo->end_offs >= j);
					if (!old)
						err = drsym_lookup_address (mod_array[i].info->full_path, j, syminfo, DRSYM_LEAVE_MANGLED);
					if (old || err == DRSYM_SUCCESS || err == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
						dr_printf("\t\t- basic_block " PFX " - [%08x -- %08x] %s\n", mod_array[i].base + j, syminfo->start_offs, syminfo->end_offs, syminfo->name);	
					} else {
						dr_printf("\t\t- basic_block " PFX "\n", mod_array[i].base + j);
					}
				}
			}
		}
		dr_free_module_data(mod_array[i].info);
		if (mod_array[i].bitmap != NULL)
			free(mod_array[i].bitmap);
	}
	dr_mutex_unlock(mod_lock);
	dr_mutex_destroy(mod_lock);
	free_drsmy_info(syminfo);
    dr_exit_process(0);
	dr_printf("Instrumentation results:\n%10d basic block executions\n", global_count);
}

static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating) {
	int i;
	for (i = 0; i < mod_count; i++) {
		global_count++;
		unsigned long tag_pc = (unsigned long)tag;
        if (mod_array[i].base <= tag_pc && mod_array[i].end >= tag_pc) {
			mod_array[i].count++;
			if (mod_array[i].bitmap != NULL)
				mod_array[i].bitmap[tag_pc - mod_array[i].base] = 1;
			break;
		}
	}
	return DR_EMIT_DEFAULT;
}

static bool module_data_same(const module_data_t *d1, const module_data_t *d2) {
	if (d1->start == d2->start && d1->end == d2->end && d1->entry_point == d2->entry_point &&
		dr_module_preferred_name(d1) != NULL && dr_module_preferred_name(d2) != NULL &&
		strcmp(dr_module_preferred_name(d1), dr_module_preferred_name(d2)) == 0)
		return true;
	return false;
}

static void event_module_load(void *drcontext, const module_data_t *info, bool loaded) {
	int i;
	dr_log(drcontext, DR_LOG_ALL, 1, "Module load event: %s [%s]\n", dr_module_preferred_name(info) , info->full_path);
	dr_mutex_lock(mod_lock);
	for (i = 0; i < mod_count; i++) {
		if (!mod_array[i].loaded && module_data_same(mod_array[i].info, info)) {
			mod_array[i].loaded = true;
			break;
        	}
	}
	if (i == mod_count) {
        	mod_array[i].base   = (unsigned long)info->start;
		mod_array[i].end    = (unsigned long)info->end;
		mod_array[i].loaded = true;
		mod_array[i].info   = dr_copy_module_data(info);
		mod_array[i].count   = 0;
		mod_array[i].size   = mod_array[i].end-mod_array[i].base;
		mod_array[i].bitmap = (byte*) malloc(mod_array[i].size);
		mod_count++;
	}
	dr_mutex_unlock(mod_lock);
}

static void event_module_unload(void *drcontext, const module_data_t *info) {
	int i;
	dr_log(drcontext, DR_LOG_ALL, 1, "Module unload event: %s [%s]\n", dr_module_preferred_name(info) , info->full_path);
	dr_mutex_lock(mod_lock);
	for (i = 0; i < mod_count; i++) {
		if (mod_array[i].loaded && module_data_same(mod_array[i].info, info)) {
			mod_array[i].loaded = false;
			break;
		}
	}
	dr_mutex_unlock(mod_lock);
}
