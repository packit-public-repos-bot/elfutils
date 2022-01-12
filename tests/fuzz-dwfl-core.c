#include <assert.h>
#include <config.h>
#include <inttypes.h>
#include <stdlib.h>
#include ELFUTILS_HEADER(dwfl)
#include "fuzz.h"
#include "system.h"

/* This fuzz target was initially used to fuzz systemd and
   there elfutils is hidden behind functions receiving file
   names and file descriptors. To cover that code the fuzz
   target converts bytes it receives into temporary files
   and passes their file descriptors to elf_begin instead of calling
   something like elf_memory (which can process bytes directly).
   New fuzzers covering elfutils should avoid this pattern.  */

static const Dwfl_Callbacks core_callbacks =
  {
    .find_elf = dwfl_build_id_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
  };

static int
module_callback (Dwfl_Module *mod, void **userdata __attribute__((unused)),
		 const char *name, Dwarf_Addr start,
		 void *arg __attribute__((unused)))
{
  /* Forces resolving of main elf and debug files. */
  Dwarf_Addr bias;
  Elf *elf = dwfl_module_getelf (mod, &bias);
  Dwarf *dwarf = dwfl_module_getdwarf (mod, &bias);

  Dwarf_Addr end;
  const char *mainfile;
  const char *debugfile;
  const char *modname = dwfl_module_info (mod, NULL, NULL, &end, NULL,
                                          NULL, &mainfile, &debugfile);
  if (modname == NULL || strcmp (modname, name) != 0)
    {
      end = start + 1;
      mainfile = NULL;
      debugfile = NULL;
    }

  const unsigned char *id;
  GElf_Addr id_vaddr;
  int id_len = dwfl_module_build_id (mod, &id, &id_vaddr);
  if (id_len > 0)
    {
      printf ("  [");
      do
	printf ("%02" PRIx8, *id++);
      while (--id_len > 0);
      printf ("]\n");
    }

  if (elf != NULL)
    printf ("  %s\n", mainfile != NULL ? mainfile : "-");
  if (dwarf != NULL)
    printf ("  %s\n", debugfile != NULL ? debugfile : "-");

  return DWARF_CB_OK;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  char name[] = "/tmp/fuzz-dwfl-core.XXXXXX";
  int fd = -1;
  off_t offset;
  ssize_t n;
  Elf *core = NULL;
  Dwfl *dwfl = NULL;

  fd = mkstemp (name);
  assert (fd >= 0);

  n = write_retry (fd, data, size);
  assert (n >= 0);

  offset = lseek (fd, 0, SEEK_SET);
  assert (offset == 0);

  elf_version (EV_CURRENT);
  core = elf_begin (fd, ELF_C_READ_MMAP, NULL);
  if (core == NULL)
    goto cleanup;
  dwfl = dwfl_begin (&core_callbacks);
  assert(dwfl != NULL);
  if (dwfl_core_file_report (dwfl, core, NULL) < 0)
    goto cleanup;
  if (dwfl_report_end (dwfl, NULL, NULL) != 0)
    goto cleanup;
  if (dwfl_getmodules (dwfl, module_callback, NULL, 0) != 0)
    goto cleanup;

cleanup:
  dwfl_end (dwfl);
  elf_end (core);
  close (fd);
  unlink (name);
  return 0;
}
