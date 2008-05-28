/* $Header$
 *
 * Disk geometry checking utility
 *
 * Copyright (C)2007-2008 Valentin Hilbig <webmaster@scylla-charybdis.com>
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
 * Revision 1.11  2008-05-28 10:44:15  tino
 * write mode showed a too high count on EOF
 *
 * Revision 1.10  2008-05-27 17:58:03  tino
 * More output fixes
 *
 * Revision 1.9  2008-05-27 17:33:41  tino
 * Option quiet activated
 *
 * Revision 1.8  2008-05-27 16:44:20  tino
 * Next dist
 *
 * Revision 1.7  2007-12-30 15:53:14  tino
 * Option -expand
 *
 * Revision 1.6  2007-12-30 03:05:56  tino
 * Bugfix for -dump
 *
 * Revision 1.5  2007-12-10 03:01:43  tino
 * dist
 *
 * Revision 1.4  2007-09-18 03:24:42  tino
 * Usage made better
 *
 * Revision 1.3  2007/09/18 03:15:09  tino
 * Minor BUG removed.
 *
 * Revision 1.2  2007/09/18 03:08:53  tino
 * Forgot the Copyright.
 */

#include "tino/alarm.h"
#include "tino/file.h"
#include "tino/getopt.h"
#include "tino/xd.h"
#include "tino/alloc.h"
#include "tino/err.h"
#include "tino/md5.h"

#include <time.h>

#include "diskus_version.h"

#define	SECTOR_SIZE		512
#define	MAX_SECTOR_SIZE		SECTOR_SIZE
#define	DISKUS_MAGIC_SIZE	27

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

struct diskus_cfg
  {
    int		bs, async;
    const char	*mode;
    long long	nr, pos;
    TINO_DATA	*stdout;
    int		signpos;
    int		err, errtype;
    int		idpos;
    int		expand;
    int		quiet;
    int		retflags;
    long long	ts;
  };

#define	CFG	struct diskus_cfg *cfg

static int
print_state(void *user, long delta, time_t now, long runtime)
{
  struct diskus_cfg	*cfg=user;

  if (cfg->quiet)
    return cfg->quiet==1 ? 0 : 1;

  fprintf(stderr, "%ld:%02d %s %lld %lldMB %d \r", runtime/60, (int)(runtime%60), cfg->mode, cfg->nr, cfg->pos>>20, cfg->err);
  fflush(stderr);

  return 0;
}

static void
read_worker(CFG, unsigned char *ptr, size_t len)
{
  cfg->nr	+= len/SECTOR_SIZE;
  cfg->pos	+= len;
}

static void
dump_flush(CFG, unsigned char *buf, int fill)
{
  if (fill)
    tino_xd(cfg->stdout, "", -10, cfg->pos-fill, buf, fill);
}

static void
dump_worker(CFG, unsigned char *ptr, size_t len)
{
  static unsigned char	buf[16];
  static int		fill, unchanged;
  int			i;

  if (!ptr)
    {
      dump_flush(cfg, buf, fill);
      if (!len)
        tino_xd(cfg->stdout, "", -10, cfg->pos, NULL, 0);
      fill	= 0;
      unchanged	= 0;
      return;
    }
  cfg->nr	+= len/SECTOR_SIZE;
  for (i=0; i<len; )
    {
      register unsigned char	c;

      if (unchanged==2 && fill==0)
	{
	  while (i+16<=len && !memcmp(ptr+i, buf, 16))
	    {
	      cfg->pos	+= 16;
	      i		+= 16;
	    }
	  if (i>=len)
	    break;
	}

      c	=  ptr[i];
      if (buf[fill]!=c)
	{
	  buf[fill]	= c;
	  unchanged	= 0;
	}
      i++;
      cfg->pos++;
      if (++fill<16)
	continue;

      if (unchanged==0 || cfg->expand)
	{
	  unchanged	= 1;
	  dump_flush(cfg, buf, fill);
	  fill		= 0;
	  continue;
	}
      fill	= 0;
      if (unchanged==1)
	tino_data_printfA(cfg->stdout, "*\n");
      unchanged	= 2;
    }
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
check_worker(CFG, unsigned char *ptr, size_t len)
{
  int		i;
  unsigned char	sect[MAX_SECTOR_SIZE];

  if (!ptr)
    return;

  for (i=0; i<len; i+=SECTOR_SIZE, ptr+=SECTOR_SIZE, cfg->nr++)
    {
      int	off;
      char	*end;
      long long	cmp, ts;

      if (cfg->expand)
	cfg->errtype	= 0;
      if ((off=find_signature(cfg, ptr))<0)
	{
	  if (cfg->errtype!=1)
	    tino_data_printfA(cfg->stdout, "cannot find signature in sector %lld\n", cfg->nr);
	  cfg->retflags	|= diskus_ret_diff;
	  cfg->errtype	= 1;
	  cfg->err++;
	  continue;
	}
      end	= 0;
      cmp	= strtoll((char *)(ptr+off+8), &end, 16);
      if (!end || *end!=' ')
	{
	  if (cfg->errtype!=2)
	    tino_data_printfA(cfg->stdout, "invalid signature(1) in sector %lld\n", cfg->nr);
	  cfg->retflags	|= diskus_ret_diff;
	  cfg->errtype	= 2;
	  cfg->err++;
	  continue;
	}
      if (cmp!=cfg->nr)
	{
	  if (cfg->errtype!=3)
	    tino_data_printfA(cfg->stdout, "signature number mismatch (%lld) in sector %lld\n", cmp, cfg->nr);
	  cfg->retflags	|= diskus_ret_diff;
	  cfg->errtype	= 3;
	  cfg->err++;
	  continue;
	}
      ts	= strtoll(end+1, &end, 10);
      if (ts!=cfg->ts && cfg->ts)
	{
	  tino_data_printfA(cfg->stdout, "timestamp jumped from %lld to %lld\n", cfg->ts, ts);
	  cfg->retflags	|= diskus_ret_old;
	}
      cfg->ts	= ts;
      if (!end || *end!=']')
	{
	  if (cfg->errtype!=4)
	    tino_data_printfA(cfg->stdout, "invalid signature(2) in sector %lld\n", cfg->nr);
	  cfg->retflags	|= diskus_ret_diff;
	  cfg->errtype	= 4;
	  cfg->err++;
	  continue;
	}
      create_sector(cfg->nr, sect, (char *)(ptr+off), (end-(char *)ptr)-off+1);
      if (memcmp(ptr, sect, SECTOR_SIZE))
	{
	  if (cfg->errtype!=5)
	    tino_data_printfA(cfg->stdout, "data mismatch in sector %lld\n", cfg->nr);
	  cfg->retflags	|= diskus_ret_diff;
	  cfg->errtype	= 5;
	  cfg->err++;
	  continue;
	}
    }
  cfg->pos	+= len;
}

static void
gen_worker(CFG, unsigned char *ptr, size_t len)
{
  int		i;
  char		id[64];

  if (!ptr)
    return;

  for (i=0; i<len; i+=SECTOR_SIZE, ptr+=SECTOR_SIZE)
    {
      snprintf(id, sizeof id, "[DISKUS %016llx %lld]", cfg->nr, (long long)cfg->ts);
      create_sector(cfg->nr, ptr, id, strlen(id));
      cfg->nr++;
    }
  cfg->pos	+= len;
}

static void
null_worker(CFG, unsigned char *ptr, size_t len)
{
  static size_t	flag;

  if (!ptr)
    {
      flag	= 0;
      return;
    }
  if (flag!=len)
    {
      memset(ptr, 0, len);
      flag	= len;
    }
  cfg->pos	+= len;
}

typedef void	worker_fn(CFG, unsigned char *, size_t);

static int
run_read(CFG, const char *name, worker_fn worker)
{
  int		fd, got;
  void		*block;

  block		= tino_allocO(cfg->bs);
  if ((fd=tino_file_openE(name, O_RDONLY|(cfg->async ? 0 : O_DIRECT)))<0)
    {
      tino_err(TINO_ERR(ETTDU100E,%s)" (cannot open)", name);
      return diskus_ret_param;
    }
  if (tino_file_read_allE(fd, block, cfg->bs)<0)
    {
      tino_file_closeE(fd);
      if ((fd=tino_file_openE(name, O_RDONLY|(cfg->async ? O_DIRECT : 0)))<0)
	{
	  tino_err(TINO_ERR(ETTDU100E,%s)" (cannot open)", name);
	  return diskus_ret_param;
	}
      if (!cfg->quiet)
	fprintf(stderr, "WTTDU108W (opened with reverse option -async)\n");
    }
  cfg->nr	= cfg->pos/(unsigned long long)SECTOR_SIZE;
  if (tino_file_lseekE(fd, cfg->pos, SEEK_SET)!=cfg->pos)
    {
      tino_err(TINO_ERR(ETTDU106E,%s)" (cannot seek to %lld)", name, cfg->pos);
      return diskus_ret_seek;
    }
  worker(cfg, NULL, 1);
  while ((got=tino_file_read_allE(fd, block, cfg->bs))>0)
    {
      if (got%SECTOR_SIZE)
	{
	  tino_err(TINO_ERR(ETTDU109E,%s)" (partial sector read: %d pos=%lld (%lld+%d))", name, got%SECTOR_SIZE, cfg->pos+got, cfg->pos, got);
	  return diskus_ret_short;
	}
      worker(cfg, block, got);
      TINO_ALARM_RUN();
    }
  if (got<0 || tino_file_closeE(fd))
    {
      tino_err(TINO_ERR(ETTDU101E,%s)" (read error at sector %lld pos=%lldMB)", name, cfg->nr, cfg->pos>>20);
      return diskus_ret_read;
    }
  worker(cfg, NULL, 0);
  return 0;
}

static int
run_write(CFG, const char *name, worker_fn worker)
{
  int		fd, put;
  void		*block;

  cfg->ts	= time(NULL);
  if ((fd=tino_file_openE(name, O_WRONLY|(cfg->async ? 0 : O_SYNC)))<0)
    {
      tino_err(TINO_ERR(ETTDU104E,%s)" (cannot open for write)", name);
      return diskus_ret_param;
    }
  cfg->nr	= 0;
  if (cfg->pos)
    {
      cfg->nr	= cfg->pos/SECTOR_SIZE;
      if (tino_file_lseekE(fd, cfg->pos, SEEK_SET)!=cfg->pos)
	{
	  tino_err(TINO_ERR(ETTDU106E,%s)" (cannot seek to %lld)", name, cfg->pos);
	  return diskus_ret_seek;
	}
    }
  block		= tino_allocO(cfg->bs);
  worker(cfg, NULL, 0);
  do
    {
      worker(cfg, block, cfg->bs);
      TINO_ALARM_RUN();
    } while ((put=tino_file_write_allE(fd, block, cfg->bs))==cfg->bs);
  
  if (put>=0 && errno==ENOSPC)
    {
      int	over;

      /* correct the counts as EOF usually has a short write
       */
      over	= cfg->bs - put;
      if (over%SECTOR_SIZE)
	{
	  tino_err(TINO_ERR(ETTDU109E,%s)" (partial sector written: %d pos=%lld (%lld+%d))", name, put%SECTOR_SIZE, cfg->pos-over, cfg->pos-cfg->bs, put);
	  return diskus_ret_short;
	}
      cfg->pos	-= over;
      cfg->nr	-= over/SECTOR_SIZE;
      errno	= 0;
    }
  if (errno || tino_file_closeE(fd))
    {
      tino_err(TINO_ERR(ETTDU105E,%s)" (write error at sector %lld pos=%lldMB)", name, cfg->nr, cfg->pos>>20);
      return diskus_ret_write;
    }
  return diskus_ret_ok;
}

typedef int diskus_run_fn(CFG, const char *name, worker_fn worker);

static int
run_it(CFG, diskus_run_fn *run, const char *name, worker_fn worker)
{
  int	ret;

  ret	= run(cfg, name, worker);
  if (ret || cfg->err)
    {
      if (!cfg->quiet)
        tino_data_printfA(cfg->stdout, "failed mode %s sector %lld pos=%lldMB+%lld: errs=%d ret=%d\n", cfg->mode, cfg->nr, cfg->pos>>20, cfg->pos&((1ull<<20)-1), cfg->err, ret);
    }
  else if (!cfg->quiet)
    tino_data_printfA(cfg->stdout, "success mode %s sector %lld pos=%lldMB+%lld\n", cfg->mode, cfg->nr, cfg->pos>>20, cfg->pos&((1ull<<20)-1));
  return cfg->retflags|ret;
}

int
main(int argc, char **argv)
{
  static struct diskus_cfg	cfg;
  int		argn, writemode;
  worker_fn	*fn;
  diskus_run_fn	*run;

  argn	= tino_getopt(argc, argv, 1, 1,
		      TINO_GETOPT_VERSION(DISKUS_VERSION)
		      " blockdev\n"
		      "	This is a disk geometry checking tool.  It writes sectors\n"
		      "	with individual IDs which later can be checked."
		      ,

		      TINO_GETOPT_USAGE
		      "help	this help"
		      ,

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
		      "bs N	Blocksize to operate on\n"
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
		      "dump	'dump' mode, to hexdump of output (default)"
		      , &cfg.mode,
		      mode_dump,

		      TINO_GETOPT_FLAG
		      "expand	Do not compress output, always print everything\n"
		      "		for -check and -dump"
		      , &cfg.expand,

		      TINO_GETOPT_STRINGFLAGS
		      TINO_GETOPT_MIN
		      "gen	'gen' mode, create unique test data for check mode"
		      , &cfg.mode,
		      mode_gen,
#if 0
		      TINO_GETOPT_INT
		      TINO_GETOPT_DEFAULT
		      TINO_GETOPT_MAX
		      "idpos	position of the ID string in the sector\n"
		      "		The ID usually is 36 byte long.  It cannot wrap in the sector\n"
		      "		so if the position is too high it lands somewhere else.\n"
		      "		negative values make the ID roam, that is, it's position moves.\n"
		      "		Use a high negative prime number to make it look like random"
		      , &cfg.idpos,
		      -1,
		      4096-36+1,

		      TINO_GETOPT_STRING
		      "log file	Output full log to file"
		      , &cfg.logfile,
#endif
		      TINO_GETOPT_STRING
		      TINO_GETOPT_DEFAULT
		      "mode X	set mode to operate in (dump, etc.)"
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
		      "out	define the output pattern for option -pattern"
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
		      "quiet	quiet mode, print no progress meter and no result.\n"
		      "		Success only is signalled in the return status"
		      , &cfg.quiet,

		      TINO_GETOPT_STRINGFLAGS
		      TINO_GETOPT_MIN
		      "read	'read' mode, just read data, do not output anything"
		      , &cfg.mode,
		      mode_read,

		      TINO_GETOPT_LLONG
		      TINO_GETOPT_SUFFIX
		      "start N	start position, add suffix BKMGT for Byte, KB, MB ..\n"
		      "		Must be a multiple of the sector size (512 or 4096)"
		      , &cfg.pos,
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
		      "write	write mode, destroy data (mode 'gen' needs this)"
		      , &writemode,

		      NULL
		      );
  if (argn<=0)
    return diskus_ret_param;

  if (cfg.pos&(SECTOR_SIZE-1))
    {
      if (cfg.quiet)
	tino_err(TINO_ERR(ETTDU107W,%lld)" (start value not multiple of sector size)", cfg.pos&(SECTOR_SIZE-1));
      else
	fprintf(stderr, "WTTDU107W %lld (rounded down start value)\n", cfg.pos&(SECTOR_SIZE-1));
      cfg.pos	&= ~(unsigned long long)(SECTOR_SIZE-1);
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

  if (!fn)
    {
      tino_err(TINO_ERR(ETTDU102F,%s)" (unknown mode)", cfg.mode);
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
      tino_err(TINO_ERR(ETTDU103F,%s)" (mode needs write option)", cfg.mode);
      return diskus_ret_param;
    }
  return run_it(&cfg, run, argv[argn], fn);
}
