#include <stddef.h>
#include <dr_api.h>
#include <drsyms.h>
#include <string.h>

// This `tracer` is simplified to simply record which blocks are run
// instead of the order in which they're executed. Technically it's
// more of a `hit counter` than a tracer.
#define DEBUG

#define MAX_MODS 256
static void event_exit(void);
static dr_emit_flags_t on_event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating);
static void on_event_module_load(void *drcontext, const module_data_t *info, bool loaded);
static void on_event_module_unload(void *drcontext, const module_data_t *info);
static int global_count;

// structure to track information about loaded libraries and programs (modules)
// in memory
typedef struct _module_array_t {
	unsigned long base;
	unsigned long end;
	unsigned int count;
	size_t size;
	bool   loaded;
	module_data_t *info;
	byte* bitmap;
} module_array_t;

static module_array_t module_data[MAX_MODS];
static int module_count = 0;
static void *module_lock;

DR_EXPORT void dr_init(client_id_t id) {
	module_lock = dr_mutex_create(); // Mutex used to guard accesses to module_data
    global_count = 0; // Number of blocks executed

    // Register four functions to run at various events in the program
	dr_register_exit_event(event_exit);                     // Target exits
	dr_register_bb_event(on_event_basic_block);                // Basic block is about to be run
	dr_register_module_load_event(on_event_module_load);       // A shared library is loaded
	dr_register_module_unload_event(on_event_module_unload);   // A shared library is unloaded

	dr_log(NULL, DR_LOG_ALL, 1, "Client 'MyTracer' initializing\n");	
}

static void free_drsmy_info(drsym_info_t * info) {
    if (info == NULL) {
        return;
    }
	if (info->file != NULL) 
		free(info->file);
	if (info->name != NULL) 
		free(info->name);
	free(info);
}

static void event_exit(void) {
  	dr_fprintf(STDERR, "info: EXIT");
    int i;
	size_t j;
	drsym_init(0);
	drsym_error_t err;

	drsym_info_t* syminfo;
	syminfo = malloc(sizeof(drsym_info_t));
	syminfo->struct_size = sizeof(drsym_info_t);
	syminfo->debug_kind = DRSYM_SYMBOLS;	
	syminfo->name_size = 256;
	syminfo->file_size = 256;
	syminfo->file=malloc(256);
	syminfo->name=malloc(256);

	dr_mutex_lock(module_lock);
	dr_printf("\n===\nModules:\n");
	for (i = 0; i < module_count; i++) {
        if (module_data[i].info == NULL) {
          dr_printf("\t ERROR: module %d is missing data - ignoring it [PART 2 failure]\n", i);
          continue;
        }

		syminfo->start_offs = 0;
		syminfo->end_offs = 0;
		dr_printf("\t- [%c] (%8d) %s [%s]\n", (module_data[i].loaded ? '+':'-'), module_data[i].count, dr_module_preferred_name(module_data[i].info) , module_data[i].info->full_path);

		if (module_data[i].bitmap != NULL) {
			for(j=0; j < module_data[i].size; j++) {
				if (module_data[i].bitmap[j] != 0) {
					int old = (syminfo->start_offs <= j && syminfo->end_offs >= j);
					if (!old)
						err = drsym_lookup_address (module_data[i].info->full_path, j, syminfo, DRSYM_LEAVE_MANGLED);
					if (old || err == DRSYM_SUCCESS || err == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
						dr_printf("\t\t- basic_block " PFX " - [%08x -- %08x] %s\n", module_data[i].base + j, syminfo->start_offs, syminfo->end_offs, syminfo->name);	
					} else {
						dr_printf("\t\t- basic_block " PFX "\n", module_data[i].base + j);
					}
				}
			}
		}
		dr_free_module_data(module_data[i].info);
		if (module_data[i].bitmap != NULL)
			free(module_data[i].bitmap);
	}
	dr_mutex_unlock(module_lock);

    // PART 1: global_count should not be zero - instead it should be the total number of basic
    // blocks executed. Modify the program elsewhere to update this variable as approperiate
	dr_printf("Instrumentation results:\n%10d basic block executions\n", global_count);
    if (global_count == 0) {
        dr_printf("\t ^ [PART 1 failure]\n");
    }

    // Cleanu up and exit target process
	dr_mutex_destroy(module_lock);
	free_drsmy_info(syminfo);
    dr_exit_process(0);

}

static dr_emit_flags_t on_event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating) {
	for (int i = 0; i < module_count; i++) {

		unsigned long current_program_counter = (unsigned long)tag;

        if (module_data[i].base == 0 && module_data[i].end == 0)
            continue;
        
        if (module_data[i].base <= current_program_counter && module_data[i].end >= current_program_counter) {
			module_data[i].count++; // A block has been hit in this module, update total count
            // PART 3: record that *this block* was hit in this module
			break;
		}
	}
	return DR_EMIT_DEFAULT;
}

static bool module_data_same(void *drcontext, const module_data_t *d1, const module_data_t *d2) {
    if (d1 == NULL || d2 == NULL) {
        return d1 == d2; // If both NULL we can say they're the same, else one isn't null
    }
    //dr_log(drcontext, DR_LOG_ALL, 1, "=== Comparing two modules: === \n");
    //dr_log(drcontext, DR_LOG_ALL, 1, "Module A\n\tstart at %hhn\n\tend at %hhn\n\tentry point %hhn\n\tname %s\n", d1->start, d1->end, d1->entry_point, dr_module_preferred_name(d1));
    //dr_log(drcontext, DR_LOG_ALL, 1, "Module B\n\tstart at %hhn\n\tend at %hhn\n\tentry point %hhn\n\tname %s\n", d2->start, d2->end, d2->entry_point, dr_module_preferred_name(d2));

	if (d1->start == d2->start && d1->end == d2->end && d1->entry_point == d2->entry_point &&
		dr_module_preferred_name(d1) != NULL && dr_module_preferred_name(d2) != NULL &&
		strcmp(dr_module_preferred_name(d1), dr_module_preferred_name(d2)) == 0)
		return true;
	return false;
}

static void on_event_module_load(void *drcontext, const module_data_t *info, bool loaded) {
    // A shared library has been loaded. We need to record where in memory it started, when it ended
	int i;
	dr_log(drcontext, DR_LOG_ALL, 1, "Module load event: %s [%s]\n", dr_module_preferred_name(info) , info->full_path);
	dr_mutex_lock(module_lock);

    // First - was this module previously loaded?
	for (i = 0; i < module_count; i++) {
		if (!module_data[i].loaded && module_data_same(drcontext, module_data[i].info, info)) {
			module_data[i].loaded = true;
			break;
        	}
	}

    // If the module wansn't previously loaded, we need to initialize it!
    // PART 2: Properly initialize the entry in the module array 
	if (i == module_count) {
        module_data[i].base   = (unsigned long)0; // Start of address range the module was loaded at
		module_data[i].end    = (unsigned long)0; // End of address range the module was loaded at
		module_data[i].count  = 0;                // How many blocks were run in this module?
		module_data[i].loaded = false;            // Is the module loaded?
		module_data[i].size   = 0;                // How many bytes are in this module?
		module_data[i].bitmap = (byte*)0;         // allocate a buffer of size bytes
		module_data[i].info   = (module_data_t*)0;// This should be a copy of the info varible created using the API function dr_copy_module_data

		module_count++;
	}
	dr_mutex_unlock(module_lock);
}

static void on_event_module_unload(void *drcontext, const module_data_t *info) {
    // A shared library has been unloaded, update our module_data with this information
	dr_log(drcontext, DR_LOG_ALL, 1, "Module unload event: %s [%s]\n", dr_module_preferred_name(info) , info->full_path);
	dr_mutex_lock(module_lock);
	for (int i = 0; i < module_count; i++) {
        if (module_data[i].info == NULL) {
          continue;
        }

		if (module_data[i].loaded && module_data_same(drcontext, module_data[i].info, info)) {
			module_data[i].loaded = false;
			break;
		}
	}
	dr_mutex_unlock(module_lock);
}
