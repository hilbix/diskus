/* $Header$
 *
 * Disk geometry checking utility
 *
 * Copyright (C)2007 Valentin Hilbig <webmaster@scylla-charybdis.com>
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
 * Revision 1.4  2007-09-18 03:24:42  tino
 * Usage made better
 *
 * Revision 1.3  2007/09/18 03:15:09  tino
 * Minor BUG removed.
 *
 * Revision 1.2  2007/09/18 03:08:53  tino
 * Forgot the Copyright.
 *
 * Revision 1.1  2007/09/18 03:05:46  tino
 * First version
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

static const char	mode_dump[]="dump", mode_gen[]="gen", mode_check[]="check", mode_null[]="null", mode_read[]="read";

struct diskus_cfg
  {
    int		bs, async;
    const char	*mode;
    long long	nr, pos;
    TINO_DATA	*stdout;
    int		signpos;
    int		err, errtype;
    long long	ts;
  };

#define	CFG	struct diskus_cfg *cfg

static int
print_state(void *user, long delta, time_t now, long runtime)
{
  struct diskus_cfg	*cfg=user;

  fprintf(stderr, "%ld:%02d %s %lld %lldMB %d\r", runtime/60, (int)(runtime%60), cfg->mode, cfg->nr, cfg->pos>>20, cfg->err);
  fflush(stderr);
  return 0;
}

static void
read_worker(CFG, unsigned char *ptr, size_t len)
{
  cfg->nr++;
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
      fill	= 0;
      return;
    }
  cfg->nr++;
  for (i=0; i<len; )
    {
      char	c;

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

      if (unchanged==0)
	{
	  unchanged	= 1;
	  dump_flush(cfg, buf, fill);
	  fill		= 0;
	  continue;
	}
      fill	= 0;
      if (unchanged==1)
	printf("*\n");
      unchanged	= 2;
    }
}

static void
create_sector(long long nr, unsigned char *ptr, char *id, int len)
{
  int	i;

  tino_md5_bin(id, len, ptr);
  for (i=16; i<512; i+=16)
    memcpy(ptr+i, ptr, 16);
  for (i=256; --i>=0; )
    {
      ptr[i]	^= i;
      ptr[511-i]	^= i;
    }
  memcpy(ptr+(nr%(512-len)), id, len);
}

static int
find_signature(CFG, const unsigned char *ptr)
{
  int	i, j;

  j	= cfg->signpos;
  for (i=512-27; --i>=0; )
    {
      if (!memcmp(ptr+j, "[DISKUS ", 8))
	return j;
      j++;
      j	%= 512-27;
    }
  return -1;
}

static void
check_worker(CFG, unsigned char *ptr, size_t len)
{
  int		i;
  char		sect[512];

  if (!ptr)
    return;

  for (i=0; i<len; i+=512, ptr+=512, cfg->nr++)
    {
      int	off;
      char	*end;
      long long	cmp, ts;

      if ((off=find_signature(cfg, ptr))<0)
	{
	  if (cfg->errtype!=1)
	    printf("cannot find signature in sector %lld\n", cfg->nr);
	  cfg->errtype	= 1;
	  cfg->err++;
	  continue;
	}
      end	= 0;
      cmp	= strtoll(ptr+off+8, &end, 16);
      if (!end || *end!=' ')
	{
	  if (cfg->errtype!=2)
	    printf("invalid signature(1) in sector %lld\n", cfg->nr);
	  cfg->errtype	= 2;
	  cfg->err++;
	  continue;
	}
      if (cmp!=cfg->nr)
	{
	  if (cfg->errtype!=3)
	    printf("signature number mismatch (%lld) in sector %lld\n", cmp, cfg->nr);
	  cfg->errtype	= 3;
	  cfg->err++;
	  continue;
	}
      ts	= strtoll(end+1, &end, 10);
      if (ts!=cfg->ts && cfg->ts)
	printf("timestamp jumped from %lld to %lld\n", cfg->ts, ts);
      cfg->ts	= ts;
      if (!end || *end!=']')
	{
	  if (cfg->errtype!=4)
	    printf("invalid signature(2) in sector %lld\n", cfg->nr);
	  cfg->errtype	= 4;
	  cfg->err++;
	  continue;
	}
      create_sector(cfg->nr, sect, ptr+off, (end-(char *)ptr)-off+1);
      if (memcmp(ptr, sect, 512))
	{
	  if (cfg->errtype!=5)
	    printf("data mismatch in sector %lld\n", cfg->nr);
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

  for (i=0; i<len; i+=512, ptr+=512)
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

  if ((fd=tino_file_openE(name, O_RDONLY|(cfg->async ? 0 : O_DIRECT)))<0)
    {
      tino_err(TINO_ERR(ETTDU100E,%s)" (cannot open)", name);
      return 1;
    }
  cfg->nr	= 0;
  if (cfg->pos)
    {
      cfg->nr	= cfg->pos/512;
      if (tino_file_lseekE(fd, cfg->pos, SEEK_SET)!=cfg->pos)
	{
	  tino_err(TINO_ERR(ETTDU106E,%s)" (cannot seek to %lld)", name, cfg->pos);
	  return 2;
	}
    }
  block		= tino_alloc(cfg->bs);
  worker(cfg, NULL, 0);
  while ((got=tino_file_read_allE(fd, block, cfg->bs))>0)
    {
      worker(cfg, block, got);
      TINO_ALARM_RUN();
    }
  if (got<0 || tino_file_closeE(fd))
    {
      tino_err(TINO_ERR(ETTDU101E,%s)" (read error at sector %lld pos=%lldMB)", name, cfg->nr, cfg->pos>>20);
      return 1;
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
      return 1;
    }
  cfg->nr	= 0;
  if (cfg->pos)
    {
      cfg->nr	= cfg->pos/512;
      if (tino_file_lseekE(fd, cfg->pos, SEEK_SET)!=cfg->pos)
	{
	  tino_err(TINO_ERR(ETTDU106E,%s)" (cannot seek to %lld)", name, cfg->pos);
	  return 2;
	}
    }
  block		= tino_alloc(cfg->bs);
  worker(cfg, NULL, 0);
  do
    {
      worker(cfg, block, cfg->bs);
      TINO_ALARM_RUN();
    } while ((put=tino_file_write_allE(fd, block, cfg->bs))==cfg->bs);
  if (errno || tino_file_closeE(fd))
    {
      tino_err(TINO_ERR(ETTDU105E,%s)" (write error at sector %lld pos=%lldMB)", name, cfg->nr, cfg->pos>>20);
      return 1;
    }
  return 0;
}

int
main(int argc, char **argv)
{
  static struct diskus_cfg	cfg;
  int		argn, writemode, dowrite;
  worker_fn	*fn;

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
		      "bs N	Blocksize to operate on\n"
		      "		Must be a multiple of the sector size (512 or 4096)"
		      , &cfg.bs,
		      102400,
		      512,
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

		      TINO_GETOPT_STRINGFLAGS
		      TINO_GETOPT_MIN
		      "gen	'gen' mode, create unique test data for check mode"
		      , &cfg.mode,
		      mode_gen,

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

		      TINO_GETOPT_STRINGFLAGS
		      TINO_GETOPT_MIN
		      "read	'read' mode, just read data, do not output anything"
		      , &cfg.mode,
		      mode_read,

		      TINO_GETOPT_LLONG
		      TINO_GETOPT_SUFFIX
		      "start N	start position (must be a multiple of 512)\n"
		      "		You can add a BKMGT suffix for Byte KB MB .."
		      , &cfg.pos,

		      TINO_GETOPT_FLAG
		      "write	write mode, destroy data (mode 'gen' needs this)"
		      , &writemode,

		      NULL
		      );
  if (argn<=0)
    return 1;

  dowrite	= 0;
  fn		= 0;
  if (!strcmp(cfg.mode, mode_dump))
    fn	= dump_worker;
  else if (!strcmp(cfg.mode, mode_check))
    fn	= check_worker;
  else if (!strcmp(cfg.mode, mode_read))
    fn	= read_worker;
  else if (!strcmp(cfg.mode, mode_gen))
    {
      dowrite	= 1;
      fn	= gen_worker;
    }
  else if (!strcmp(cfg.mode, mode_null))
    {
      dowrite	= 1;
      fn	= null_worker;
    }

  if (!fn)
    {
      tino_err(TINO_ERR(ETTDU102F,%s)" (unknown mode)", cfg.mode);
      return 1;
    }

#if 0
  cfg.stdout	= tino_data_stream(NULL, stdout);
#else
  cfg.stdout	= tino_data_file(NULL, 1);
#endif
  tino_alarm_set(1, print_state, &cfg);

  if (dowrite)
    {
      if (!writemode)
	{
	  tino_err(TINO_ERR(ETTDU103F,%s)" (mode needs write option)", cfg.mode);
	  return 1;
	}
      run_write(&cfg, argv[argn], fn);
    }
  else if (run_read(&cfg, argv[argn], fn))
    return 1;

  return 0;
}
