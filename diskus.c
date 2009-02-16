/* $Header$
 *
 * Disk geometry checking utility
 *
 * Copyright (C)2007-2009 Valentin Hilbig <webmaster@scylla-charybdis.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 *
 * $Log$
 * Revision 1.26  2009-02-16 07:03:04  tino
 * Option -xd fixes
 *
 * Revision 1.25  2009-02-16 05:45:21  tino
 * -null worker shall work again
 *
 * Revision 1.24  2009-02-16 05:38:51  tino
 * Initial jumps are now bound by the blocksize.
 *
 * Revision 1.23  2009-02-16 05:09:39  tino
 * Backoff fixes, however there seems to be a second bug,
 * such that it sometimes runs over the end.
 *
 * Revision 1.22  2009-01-08 20:03:44  tino
 * Fix for printed offset
 *
 * Revision 1.21  2009-01-08 20:00:35  tino
 * xd option and better reporting
 *
 * Revision 1.20  2009-01-03 15:48:57  tino
 * Output now uses scaling, more reliable read mode
 *
 * Revision 1.19  2008-12-14 01:26:16  tino
 * more future
 *
 * Revision 1.18  2008-12-14 01:09:13  tino
 * New version with -freshen and -to
 *
 * Revision 1.17  2008-10-12 21:05:35  tino
 * Updated to new library functions
 *
 * Revision 1.16  2008-09-28 17:54:53  tino
 * Backoff strategy
 *
 * Revision 1.15  2008-09-28 14:38:12  tino
 * Option -jump
 *
 * Revision 1.14  2008-09-28 12:31:46  tino
 * List possible suffixes in help
 *
 * Revision 1.13  2008-09-27 23:19:56  tino
 * Page aligned buffer gets rid of need for option -async
 *
 * Revision 1.12  2008-08-03 16:58:54  tino
 * Added error if -write is not needed
 *
 * Revision 1.11  2008-05-28 10:44:15  tino
 * write mode showed a too high count on EOF
 *
 * Revision 1.9  2008-05-27 17:33:41  tino
 * Option quiet activated
 *
 * Revision 1.7  2007-12-30 15:53:14  tino
 * Option -expand
 *
 * Revision 1.6  2007-12-30 03:05:56  tino
 * Bugfix for -dump
 *
 * Revision 1.3  2007/09/18 03:15:09  tino
 * Minor BUG removed.
 */

#include "tino/alarm.h"
#include "tino/file.h"
#include "tino/getopt.h"
#include "tino/xd.h"
#include "tino/alloc.h"
#include "tino/err.h"
#include "tino/md5.h"
#include "tino/scale.h"
#include "tino/str.h"
#if 0
#include "tino/repository.h"
#endif

#include <time.h>

#include "diskus_version.h"

#define	SECTOR_SIZE		512
#define	SKIP_BYTES		4096
#define	MAX_SECTOR_SIZE		SECTOR_SIZE
#define	DISKUS_MAGIC_SIZE	27

#define	SECTOR_OFFSET(X)	((X)&(SECTOR_SIZE-1))

/* This is a bitmask	*/
enum
  {
    diskus_ret_ok	= 0,	/* Success	*/
    diskus_ret_param	= 1,	/* Parameter error like wrong file (permission denied)	*/
    diskus_ret_seek	= 2,	/* Seek error	*/
    diskus_ret_read	= 4,	/* Read error	*/
    diskus_ret_write	= 8,	/* Write error	*/
    diskus_ret_diff	= 16,	/* Structure error (Sector X pretends to be Sector Y)	*/
    diskus_ret_short	= 32,	/* Short read	*/
    diskus_ret_old	= 64,	/* Checksum timestamp jumps	*/
  };
static const char	mode_dump[]="dump", mode_gen[]="gen", mode_check[]="check", mode_null[]="null", mode_read[]="read";
static const char	mode_freshen[]="freshen";

enum diskus_errtype
  {
    ERR_NONE	= 0,
    ERR_SIGNATURE_MISSING,
    ERR_SIGNATURE_INVALID1,
    ERR_SIGNATURE_INVALID2,
    ERR_SIGNATURE_MISMATCH,
    ERR_DATA_MISMATCH,
    ERR_READ,
  };

struct diskus_cfg
  {
    int			bs, async;
    const char		*mode;
    long long		nr, pos, endpos;
    int			fd;
    const char		*name;
    TINO_DATA		*stdout;
    int			signpos;
    int			err, errtype;
    int			idpos;
    int			expand;
    int			quiet;
    int			hexdump;
    int			retflags;
    long long		ts;
    const char		*keepfile, *update;
    /* Option -jump:	*/
    int			jump;
    unsigned long long	nxt, skip;
  };

#define	CFG	struct diskus_cfg *cfg

typedef int	diskus_worker_fn(CFG, unsigned char *, size_t);
typedef int	diskus_run_fn(CFG, diskus_worker_fn worker);

static int
print_state(void *user, long delta, time_t now, long runtime)
{
  struct diskus_cfg	*cfg=user;

  if (cfg->quiet)
    return cfg->quiet==1 ? 0 : 1;

  fprintf(stderr, "%s %s %10lldS %siB %d \r", tino_scale_interval(1, runtime, 1, -6), cfg->mode, cfg->nr, tino_scale_bytes(2, cfg->pos, 2, -9), cfg->err);
  fflush(stderr);

  return 0;
}

static const char *
get_pos_str(CFG)
{
  return tino_str_ltrim_const(tino_scale_bytes(1, cfg->pos, 2, -9));
}

/* This requires repositioning like it is done in run_read_type()
 */
static int
freshen_worker(CFG, unsigned char *ptr, size_t len)
{
  int	put;

  if (!ptr)
    return 0;

  if (tino_file_lseekE(cfg->fd, cfg->pos, SEEK_SET)!=cfg->pos)
    {
      TINO_ERR2("ETTDU120E %s: cannot seek to %lld", cfg->name, cfg->pos);
      return diskus_ret_seek;
    }
  put	= tino_file_writeI(cfg->fd, ptr, len);
  if (put<0)
    {
      TINO_ERR3("ETTDU121B %s: rewrite error at sector %lld pos=%siB", cfg->name, cfg->nr, get_pos_str(cfg));
      return -1;
    }
  if (SECTOR_OFFSET(put))
    {
      cfg->nr	+= put/SECTOR_SIZE;
      TINO_ERR6("ETTDU122A %s: partial sector %lld written: %d pos=%lld (%lld+%d)", cfg->name, cfg->nr, SECTOR_OFFSET(put), cfg->pos, cfg->pos-put, put);
      put	-= SECTOR_OFFSET(put);
      cfg->pos	+= put;
      return -1;
    }
  if (put!=len && errno!=EINTR)
    TINO_ERR5("WTTDU123A %s: short write: %d instead of %d at pos=%lld (now %lld)", cfg->name, put, len, cfg->pos, cfg->pos+put);
  if (put>SECTOR_SIZE && put>cfg->bs/2)
    put	/= 2;			/* double step freshen, such that we run over each position two times with interleaving	*/
  cfg->pos	+= put;
  cfg->nr	+= put/SECTOR_SIZE;
  return 1;	/* reseek needed	*/
}

static int
read_worker(CFG, unsigned char *ptr, size_t len)
{
  if (!ptr)
    return 0;

  cfg->nr	+= len/SECTOR_SIZE;
  cfg->pos	+= len;
  return 0;
}

static void
dump_sect(CFG, int off, unsigned char *ptr)
{
  struct tino_xd	xd;

  if (!cfg->hexdump)
    return;
  tino_xd_init(&xd, cfg->stdout, "", -10, cfg->pos+off, 1);
  tino_xd_do(&xd, ptr, SECTOR_SIZE);
  tino_xd_exit(&xd);
}

static int
dump_worker(CFG, unsigned char *ptr, size_t len)
{
  static struct tino_xd	xd;

  if (!ptr)
    {
      if (len)
	tino_xd_init(&xd, cfg->stdout, "", -10, cfg->pos, 1);
      else
	tino_xd_exit(&xd);
    }
  else
    {
      tino_xd_do(&xd, ptr, len);
      cfg->nr	+= len/SECTOR_SIZE;
      cfg->pos	+= len;
    }
  return 0;
}

static void
create_sector(long long nr, unsigned char *ptr, char *id, int len)
{
  int	i;

  tino_md5_bin(id, len, ptr);
  for (i=16; i<SECTOR_SIZE; i+=16)
    memcpy(ptr+i, ptr, 16);
  for (i=SECTOR_SIZE/2; --i>=0; )
    {
      ptr[i]	^= i;
      ptr[511-i]	^= i;
    }
  memcpy(ptr+(nr%(SECTOR_SIZE-len+1)), id, len);
}

static int
find_signature(CFG, const unsigned char *ptr)
{
  int	i, j;

  j	= cfg->signpos;
  for (i=SECTOR_SIZE-DISKUS_MAGIC_SIZE; --i>=0; )
    {
      if (!memcmp(ptr+j, "[DISKUS ", 8))
	return j;
      j++;
      j	%= SECTOR_SIZE-DISKUS_MAGIC_SIZE;
    }
  return -1;
}

static void
diskus_vlog(CFG, TINO_VA_LIST list)
{
  tino_data_printfA(cfg->stdout, "sector %llu: ", cfg->nr);
  tino_data_vsprintfA(cfg->stdout, list);
  tino_data_printfA(cfg->stdout, "\n");
  tino_data_syncA(cfg->stdout, 0);
}

static void
diskus_log(CFG, const char *text, ...)
{
  tino_va_list	list;

  tino_va_start(list, text);
  diskus_vlog(cfg, &list);
  tino_va_end(list);
}

static void
diskus_err(CFG, enum diskus_errtype err, int retflag, const char *text, ...)
{
  tino_va_list	list;

  xDP(("(%p, %d, %d, %s, ..)", cfg, err, retflag, text));

  if (cfg->errtype!=err || cfg->expand)
    {
      tino_va_start(list, text);
      diskus_vlog(cfg, &list);
      tino_va_end(list);
    }

  cfg->errtype	=  err;
  cfg->retflags	|= retflag;
  cfg->err++;
}

static int
check_worker(CFG, unsigned char *ptr, size_t len)
{
  int		i;
  unsigned char	sect[MAX_SECTOR_SIZE];

  if (!ptr)
    return 0;

  for (i=0; i<len; i+=SECTOR_SIZE, ptr+=SECTOR_SIZE, cfg->nr++)
    {
      int	off;
      char	*end;
      long long	cmp, ts;

      if (cfg->expand)
	cfg->errtype	= ERR_NONE;
      if ((off=find_signature(cfg, ptr))<0)
	{
	  diskus_err(cfg, ERR_SIGNATURE_MISSING, diskus_ret_diff, "cannot find signature");
	  dump_sect(cfg, i, ptr);
	  continue;
	}
      end	= 0;
      cmp	= strtoll((char *)(ptr+off+8), &end, 16);
      if (!end || *end!=' ')
	{
	  diskus_err(cfg, ERR_SIGNATURE_INVALID1, diskus_ret_diff, "invalid signature(1)");
	  dump_sect(cfg, i, ptr);
	  continue;
	}
      ts	= strtoll(end+1, &end, 10);
      if (!end || *end!=']')
	{
	  diskus_err(cfg, ERR_SIGNATURE_INVALID2, diskus_ret_diff, "invalid signature(2)");
	  dump_sect(cfg, i, ptr);
	  continue;
	}
      if (cmp!=cfg->nr)
	{
	  int	wrong;

	  create_sector(cmp, sect, (char *)(ptr+off), (end-(char *)ptr)-off+1);
	  wrong	= memcmp(ptr, sect, SECTOR_SIZE);
	  diskus_err(cfg, ERR_SIGNATURE_MISMATCH, diskus_ret_diff,
		     "signature number mismatch (%lld), %s data, %s timestamp",
		     cmp, (wrong ? "invalid" : "valid"), (ts==cfg->ts ? "good" : "wrong"));
	  if (wrong)
	    dump_sect(cfg, i, ptr);
	  continue;
	}
      if (ts!=cfg->ts && cfg->ts)
	{
	  diskus_log(cfg, "timestamp jumped from %lld to %lld\n", cfg->ts, ts);
	  cfg->retflags	|= diskus_ret_old;
	}
      cfg->ts	= ts;
      create_sector(cfg->nr, sect, (char *)(ptr+off), (end-(char *)ptr)-off+1);
      if (memcmp(ptr, sect, SECTOR_SIZE))
	{
	  diskus_err(cfg, ERR_DATA_MISMATCH, diskus_ret_diff, "data mismatch");
	  continue;
	}
    }
  cfg->pos	+= len;
  return 0;
}

static int
gen_worker(CFG, unsigned char *ptr, size_t len)
{
  int		i;
  char		id[64];

  if (!ptr)
    return 0;

  for (i=0; i<len; i+=SECTOR_SIZE, ptr+=SECTOR_SIZE)
    {
      snprintf(id, sizeof id, "[DISKUS %016llx %lld]", cfg->nr, (long long)cfg->ts);
      create_sector(cfg->nr, ptr, id, strlen(id));
      cfg->nr++;
    }
  cfg->pos	+= len;
  return 0;
}

static int
null_worker(CFG, unsigned char *ptr, size_t len)
{
  static size_t	flag;

  if (!ptr)
    {
      flag	= 0;
      return 0;
    }
  if (flag!=len)
    {
      memset(ptr, 0, len);
      flag	= len;
    }
  cfg->pos	+= len;
  cfg->nr	+= len/SECTOR_SIZE;
  return 0;
}

static int
backoff(CFG)
{
  unsigned long long	jump;

  /* Keep it at a power of 2
   */
  for (jump=SKIP_BYTES; jump>cfg->bs; jump>>=1);

  switch (cfg->jump)
    {
    default:
      return 1;

    case 1:
      cfg->skip	= jump;
      break;
    case 2:
      if (cfg->nxt!=cfg->pos)
	cfg->skip	= 0;
      cfg->skip	+= jump;
      break;
    case 3:
      if (cfg->nxt==cfg->pos || !cfg->skip)
	cfg->skip	+= jump;
      break;
    case 4:
      if (cfg->nxt!=cfg->pos || !cfg->skip)
	cfg->skip = jump/2;
      cfg->skip	*= 2;
      break;
    case 5:
      if (!cfg->skip)
	cfg->skip	= jump;
      else if (cfg->nxt==cfg->pos)
	cfg->skip	*= 2;
      break;
    }
  cfg->nxt	= (cfg->pos+cfg->skip)& ~(unsigned long long)(jump-1);
  return 0;
}

static int
run_read_type(CFG, int mode, int flags, diskus_worker_fn worker)
{
  int	got;
  void	*block;
  unsigned long long	nxt;

  nxt	= 0;

  if ((cfg->fd=tino_file_openE(cfg->name, mode|(cfg->async ? 0 : flags)))<0)
    {
      TINO_ERR1("ETTDU100A %s: cannot open", cfg->name);
      return diskus_ret_param;
    }
  block	= tino_alloc_alignedO(cfg->bs);
  if (tino_file_read_allE(cfg->fd, block, cfg->bs)<0)
    {
      tino_file_closeE(cfg->fd);
      if ((cfg->fd=tino_file_openE(cfg->name, mode|(cfg->async ? flags : 0)))<0)
	{
	  TINO_ERR1("ETTDU100A %s: cannot open", cfg->name);
	  return diskus_ret_param;
	}
      if (!cfg->quiet)
	TINO_ERR1("WTTDU108 %s: opened with reverse option -async", cfg->name);
    }
  if (worker(cfg, NULL, 1))
    {
      TINO_ERR1("FTTDU113A %s: internal fatal error, worker could not be initialized", cfg->name);
      return diskus_ret_param;
    }

  while (!cfg->endpos || cfg->pos<cfg->endpos)
    {
      xDP(("() pos=%llu", cfg->pos));

      if (SECTOR_OFFSET(cfg->pos))
	{
	  TINO_ERR2("FTTDU112A %s: internal fatal error, pos %lld not multiple of sector size", cfg->name, cfg->pos);
	  return diskus_ret_param;
	}

      /* Repositioning is *required* here, as the position is unknown
       * here
       */
      cfg->nr	= cfg->pos/(unsigned long long)SECTOR_SIZE;
      if (tino_file_lseekE(cfg->fd, cfg->pos, SEEK_SET)!=cfg->pos)
	{
	  TINO_ERR2("ETTDU106E %s: cannot seek to %lld", cfg->name, cfg->pos);
	  return diskus_ret_seek;
	}

      for (;;)
	{
	  long long	want;
	  int		max;

	  max	= cfg->bs;
	  if (cfg->endpos && cfg->pos+max>cfg->endpos)
	    max	= cfg->endpos-cfg->pos;

	  memset(block, 0, max);
	  TINO_ALARM_RUN();
	  got	= tino_file_readE(cfg->fd, block, max);
	  TINO_ALARM_RUN();
	  if (got<=0)
	    break;
	  
	  if (SECTOR_OFFSET(got))
	    {
	      TINO_ERR5("ETTDU109A %s: partial sector read: %d pos=%lld (%lld+%d)", cfg->name, SECTOR_OFFSET(got), cfg->pos+got, cfg->pos, got);
	      return diskus_ret_short;
	    }

	  want	= cfg->pos+got;

	  if ((got=worker(cfg, block, got))!=0)
	    break;

	  if (cfg->pos!=want || cfg->nr!=want/SECTOR_SIZE)
	    {
	      TINO_ERR1("FTTDU118A %s: internal fatal error, worker failed to update counters", cfg->name);
	      return diskus_ret_param;
	    }
	}

      if (got>0)
	continue;
      if (!got)
	break;

      if (backoff(cfg))
	{
	  TINO_ERR3("ETTDU101A %s: read error at sector %lld pos=%siB", cfg->name, cfg->nr, get_pos_str(cfg));
	  return diskus_ret_read;
	}

      diskus_err(cfg, ERR_READ, diskus_ret_read, "read error, skip %llu to sector %llu", (cfg->nxt-cfg->pos)/SECTOR_SIZE, cfg->nxt/SECTOR_SIZE);
      cfg->pos	= cfg->nxt;
    }

  if (tino_file_closeE(cfg->fd))
    {
      TINO_ERR3("ETTDU101A %s: read error at sector %lld pos=%siB", cfg->name, cfg->nr, get_pos_str(cfg));
      return diskus_ret_read;
    }
  if (worker(cfg, NULL, 0))
    {
      TINO_ERR1("FTTDU114A %s: internal fatal error, worker could not be flushed", cfg->name);
      return diskus_ret_param;
    }
  return 0;
}

static int
run_read(CFG, diskus_worker_fn worker)
{
  return run_read_type(cfg, O_RDONLY, O_DIRECT, worker);
}

static int
run_readwrite(CFG, diskus_worker_fn worker)
{
  return run_read_type(cfg, O_RDWR, O_DIRECT|O_SYNC, worker);
}

static int
run_write(CFG, diskus_worker_fn worker)
{
  int	put;
  void	*block;

  cfg->ts	= time(NULL);
  if ((cfg->fd=tino_file_openE(cfg->name, O_WRONLY|(cfg->async ? 0 : O_SYNC)))<0)
    {
      TINO_ERR1("ETTDU104A %s: cannot open for write", cfg->name);
      return diskus_ret_param;
    }
  cfg->nr	= 0;
  if (cfg->pos)
    {
      cfg->nr	= cfg->pos/SECTOR_SIZE;
      if (tino_file_lseekE(cfg->fd, cfg->pos, SEEK_SET)!=cfg->pos)
	{
	  TINO_ERR2("ETTDU106A %s: cannot seek to %lld", cfg->name, cfg->pos);
	  return diskus_ret_seek;
	}
    }
  block	= tino_alloc_alignedO(cfg->bs);
  if (worker(cfg, NULL, 0))
    {
      TINO_ERR1("FTTDU115A %s: internal fatal error, worker could not be initialized", cfg->name);
      return diskus_ret_param;
    }

  put	= 0;
  while (!cfg->endpos || cfg->pos<cfg->endpos)
    {
      long long	want;
      int	max;

      max	= cfg->bs;
      if (cfg->endpos && cfg->pos+max>cfg->endpos)
	max	= cfg->endpos-cfg->pos;

      want	= cfg->pos+max;
      if (worker(cfg, block, max))
	{
	  TINO_ERR1("FTTDU116A %s: internal fatal error, worker signals error", cfg->name);
	  return diskus_ret_param;
	}
      if (cfg->pos!=want || cfg->nr!=want/SECTOR_SIZE)
	{
	  TINO_ERR1("FTTDU119A %s: internal fatal error, worker failed to update counters", cfg->name);
	  return diskus_ret_param;
	}
      TINO_ALARM_RUN();

      /* XXX bug alert.  tino_file_write_allE() may behave erratic on
       * some POSIX systems on EINTR.  However it works on Linux.
       */
      put	= tino_file_write_allE(cfg->fd, block, max);
      if (put!=max)
	{
	  /* Turn back the time to the start position
	   *
	   * This also fixes an error in versions before 0.5.0 on write errors
	   */
	  cfg->pos	-= max;
	  cfg->nr	-= max/SECTOR_SIZE;
	  break;
	}
    }
  
  if (put>=0 && errno==ENOSPC)
    {
      /* correct the counts to the current position
       */
      if (SECTOR_OFFSET(put))
	{
	  TINO_ERR5("ETTDU109A %s: partial sector written: %d pos=%lld (%lld+%d)", cfg->name, SECTOR_OFFSET(put), cfg->pos+put, cfg->pos, put);
	  return diskus_ret_short;
	}
      cfg->pos	+= put;
      cfg->nr	-= put/SECTOR_SIZE;
      errno	= 0;
    }
  if (errno || tino_file_closeE(cfg->fd))
    {
      TINO_ERR3("ETTDU105A %s: write error at sector %lld pos=%siB", cfg->name, cfg->nr, get_pos_str(cfg));
      return diskus_ret_write;
    }
  return diskus_ret_ok;
}

static int
run_it(CFG, diskus_run_fn *run, const char *name, diskus_worker_fn worker)
{
  int		ret;
  time_t	start, now;

  cfg->name	= name;
  time(&start);
  ret	= run(cfg, worker);
  time(&now);
  now	-= start;
  if (ret || cfg->err)
    {
      if (!cfg->quiet)
        tino_data_printfA(cfg->stdout, "failed %s mode %s sector %lld pos=%lldMiB+%lld: errs=%d ret=%d\n", tino_scale_interval(1, (long)now, 2, 4), cfg->mode, cfg->nr, cfg->pos>>20, cfg->pos&((1ull<<20)-1ull), cfg->err, ret);
    }
  else if (!cfg->quiet)
    tino_data_printfA(cfg->stdout, "success %s mode %s sector %lld pos=%lldMiB+%lld\n", tino_scale_interval(1, (long)now, 2, 4), cfg->mode, cfg->nr, cfg->pos>>20, cfg->pos&((1ull<<20)-1ull));
  return cfg->retflags|ret;
}

int
main(int argc, char **argv)
{
  static struct diskus_cfg	cfg;
  int		argn, writemode;
  diskus_worker_fn	*fn;
  diskus_run_fn	*run;

  argn	= tino_getopt(argc, argv, 1, 1,
		      TINO_GETOPT_VERSION(DISKUS_VERSION)
		      " blockdev\n"
		      "	This is a disk geometry checking and limited repair tool.\n"
		      "	It writes sectors with individual IDs which later can be\n"
		      "	checked.  Or it can 'freshen' (rewrite) all sector data."
		      ,

		      TINO_GETOPT_USAGE
		      "help	this help"
		      ,
		      /*y*/

		      TINO_GETOPT_FLAG
		      "async	Do not use O_SYNC nor O_DIRECT\n"
		      "		This option makes error reporting less reliable"
		      , &cfg.async,

		      TINO_GETOPT_INT
		      TINO_GETOPT_DEFAULT
		      TINO_GETOPT_SUFFIX
		      TINO_GETOPT_MIN
		      TINO_GETOPT_MAX
#if 0
		      TINO_GETOPT_MIN_PTR
#endif
		      "bs N	Blocksize to operate on (suffix hint: BSKCMGTPEZY)\n"
		      "		Must be a multiple of the sector size (512 or 4096)"
#if 0
		      , &cfg.vary	/* min_ptr	*/
#endif
		      , &cfg.bs,
		      102400,
		      SECTOR_SIZE,
		      16*1024*1024,

		      TINO_GETOPT_STRINGFLAGS
		      TINO_GETOPT_MIN
		      "check	'check' mode, check data written by 'gen'"
		      , &cfg.mode,
		      mode_check,

		      TINO_GETOPT_STRINGFLAGS
		      TINO_GETOPT_MIN
		      "dump	'dump' mode, do hexdump of output (default)"
		      , &cfg.mode,
		      mode_dump,

		      TINO_GETOPT_FLAG
		      "expand	Do not compress output, always print everything\n"
		      "		for -check and -dump"
		      , &cfg.expand,

		      TINO_GETOPT_STRINGFLAGS
		      TINO_GETOPT_MIN
		      "freshen  'freshen' mode, write data which was read.\n"
		      "		This updates the data again after it was read.\n"
		      "		This, of course, needs -write."
		      , &cfg.mode,
		      mode_freshen,

		      TINO_GETOPT_STRINGFLAGS
		      TINO_GETOPT_MIN
		      "gen	'gen' mode, create unique test data for check mode"
		      , &cfg.mode,
		      mode_gen,
#if 0
		      TINO_GETOPT_INT
		      TINO_GETOPT_DEFAULT
		      TINO_GETOPT_MAX
		      "idpos	Position of the ID string in the sector\n"
		      "		The ID usually is 36 byte long.  It cannot wrap in the sector\n"
		      "		so if the position is too high it lands somewhere else.\n"
		      "		Negative values make the ID roam, that is, it's position moves.\n"
		      "		Use a high negative prime number to make it look like random"
		      , &cfg.idpos,
		      -1,
		      SECTOR_SIZE-36,
#endif
		      TINO_GETOPT_FLAG
		      TINO_GETOPT_MAX
		      "jump	Try to jump over IO errors.  VERY EXPERIMENTAL FEATURE!\n"
		      "		Skips to the next 4096 byte boundary on errors.\n"
		      "		Use multiply to increase backoff strategy.\n"
		      "		(Currently only works for read modes.)\n"
		      "		To see all errors combine with option -expand.\n"
		      "		Does not work reliably if option -async is active"
		      , &cfg.jump,
		      5,
#if 0
		      TINO_GETOPT_STRING
		      "keep file	Use a file to Keep status, created if not exiting.\n"
		      "		Use option -update to re-run on certain sectors."
		      , &cfg.keepfile,
#endif
#if 0
		      TINO_GETOPT_STRING
		      "log file	Output full log to file"
		      , &cfg.logfile,
#endif
		      TINO_GETOPT_STRING
		      TINO_GETOPT_DEFAULT
		      "mode X	 Set mode to operate in (dump, etc.)"
		      , &cfg.mode,
		      mode_dump,

		      TINO_GETOPT_STRINGFLAGS
		      TINO_GETOPT_MIN
		      "null	'null' mode, write NUL to drive"
		      , &cfg.mode,
		      mode_null,
#if 0
		      TINO_GETOPT_STRING
		      TINO_GETOPT_DEFAULT
		      "out	Define the OUTput pattern for option -pattern"
		      , &cfg.outpattern,
		      "0x55 0xaa",

		      TINO_GETOPT_STRINGFLAGS
		      TINO_GETOPT_MIN
		      "pattern	'pattern' mode, write a pattern to drive\n"
		      "		The pattern is defined with the option -out"
		      , &cfg.mode,
		      mode_pattern,
#endif
		      TINO_GETOPT_FLAG
		      "quiet	Quiet mode, print no progress meter and no result.\n"
		      "		Success only is signalled in the return status"
		      , &cfg.quiet,

		      TINO_GETOPT_STRINGFLAGS
		      TINO_GETOPT_MIN
		      "read	'read' mode, just read data, do not output anything"
		      , &cfg.mode,
		      mode_read,

		      TINO_GETOPT_LLONG
		      TINO_GETOPT_SUFFIX
		      "start N  Start position N, suffix BKMGTPEZY for Byte, KiB, MiB..\n"
		      "		Must be a multiple of the sector size (512 or 4096)\n"
		      "		Use suffix 'S'ector (512) or 'C'D-Rom (4096)."
		      , &cfg.pos,

		      TINO_GETOPT_LLONG
		      TINO_GETOPT_SUFFIX
		      "to N	End position N, N like in -start option.\n"
		      "		Use a negative number to give the offset to -start"
		      , &cfg.endpos,
#if 0
		      TINO_GETOPT_STRING
		      "update R	Update Range for option -keep.  Range is: Letter[From][-To]..\n"
		      "		From/To are positions with suffix as usual.\n"
		      "		O/V	Sectors read OK/Verified (=with correct timestamp)\n"
		      "		R/W/E/A	Sectors with Read/Write/both/any Errors\n"
		      "		N/G	Sectors Nulled/Generated\n"
		      "		S/P/M	Sectors Skipped/Past EOF/Missing (=not yet read)"
		      , &cfg.update,
#endif
#if 0
		      TINO_GETOPT_INT
		      TINO_GETOPT_SUFFIX
		      TINO_GETOPT_MIN
		      TINO_GETOPT_MAX_PTR
		      "vary N	Vary blocksize from this value to the one given above\n"
		      "		Must be a multiple of the sector size (512 or 4096)"
		      , &cfg.bs	/* max_ptr	*/
		      , &cfg.vary,
		      0,
#endif
		      TINO_GETOPT_FLAG
		      "write	Write mode, destroy data (mode 'gen' needs this)"
		      , &writemode,

		      TINO_GETOPT_FLAG
		      "xd	Do hexdump of sector in certain error cases"
		      , &cfg.hexdump,
#if 0
		      TINO_GETOPT_STRING
		      "zone file  Append timing information to file"
		      , &cfg.timefile,
#endif
		      NULL
		      );
  if (argn<=0)
    return diskus_ret_param;

  if (SECTOR_OFFSET(cfg.pos))
    {
      if (cfg.quiet)
	TINO_ERR1("ETTDU107I start value %lld not multiple of sector size", cfg.pos);
      TINO_ERR1("WTTDU107 rounded down start value by %lld", SECTOR_OFFSET(cfg.pos));
      cfg.pos	-= SECTOR_OFFSET(cfg.pos);
    }
  if (cfg.endpos<0)
    cfg.endpos	= cfg.pos-cfg.endpos;
  if (SECTOR_OFFSET(cfg.endpos))
    {
      if (cfg.quiet)
	TINO_ERR1("ETTDU124I end value %lld not multiple of sector size", cfg.endpos);
      TINO_ERR1("WTTDU125 rounded down end value by %lld", SECTOR_OFFSET(cfg.endpos));
      cfg.endpos -= SECTOR_OFFSET(cfg.endpos);
    }
  run		= run_read;
  fn		= 0;
  if (!strcmp(cfg.mode, mode_dump))
    fn	= dump_worker;
  else if (!strcmp(cfg.mode, mode_check))
    fn	= check_worker;
  else if (!strcmp(cfg.mode, mode_read))
    fn	= read_worker;
  else if (!strcmp(cfg.mode, mode_gen))
    {
      fn	= gen_worker;
      run	= run_write;
    }
  else if (!strcmp(cfg.mode, mode_null))
    {
      fn	= null_worker;
      run	= run_write;
    }
  else if (!strcmp(cfg.mode, mode_freshen))
    {
      fn	= freshen_worker;
      run	= run_readwrite;
    }

  if (!fn)
    {
      TINO_ERR1("FTTDU102F unknown mode %s", cfg.mode);
      return diskus_ret_param;
    }

#if 0
  cfg.stdout	= tino_data_stream(NULL, stdout);
#else
  cfg.stdout	= tino_data_file(NULL, 1);
#endif
  tino_alarm_set(1, print_state, &cfg);

  if (!writemode && run!=run_read)
    {
      TINO_ERR1("ETTDU103F %s mode needs write option", cfg.mode);
      return diskus_ret_param;
    }
  else if (writemode && run==run_read)
    {
      TINO_ERR1("ETTDU110F %s mode must not have write option", cfg.mode);
      return diskus_ret_param;
    }
  return run_it(&cfg, run, argv[argn], fn);
}
