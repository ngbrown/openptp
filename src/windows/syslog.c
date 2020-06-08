#ifdef _WIN32

#include <syslog.h>

#include <STDARG.H>
#include <stdio.h>
#include <Windows.h>

#define SYSLOG_DGRAM_SIZE 1024

static BOOL        syslog_opened = FALSE;

static int         syslog_mask = 0xFF; 
static char        syslog_ident[128] = "";
static int         syslog_facility = LOG_USER;
static char        syslog_procid_str[20];
static char        local_hostname[MAX_COMPUTERNAME_LENGTH + 1] = "";

static int   datagramm_size = SYSLOG_DGRAM_SIZE - 2;

/* Close desriptor used to write to system logger.  */
extern void closelog(void);

/* Open connection to system logger.  */
void openlog(char *ident, int option, int facility)
{
	DWORD n;

	if (syslog_opened)
		goto done;

	n = sizeof(local_hostname);
	if (!GetComputerNameA(local_hostname, &n))
		goto done;

	syslog_facility = facility ? facility : LOG_USER;

	if (option & LOG_PID)
		sprintf_s(syslog_procid_str, sizeof(syslog_procid_str), "[%lu]", GetCurrentProcessId());
	else
		syslog_procid_str[0] = '\0';

	if (ident)
		strcpy_s(syslog_ident, sizeof(syslog_ident), ident);

done:
	syslog_opened = TRUE;
}

/* Set the log mask level.  */
int setlogmask(int mask)
{
	int ret;

	ret = syslog_mask;
	if (mask)
	{
		syslog_mask = mask;
	}

	return ret;
}

/* Generate a log message using FMT string and option arguments.  */
void syslog(int pri, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

/* Generate a log message using FMT and using arguments pointed to by AP.  */
void vsyslog(int pri, char *fmt, va_list ap)
{
	static char *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	char  datagramm[SYSLOG_DGRAM_SIZE];
	SYSTEMTIME stm;
	int len;
	char *p;

	if (!(LOG_MASK(LOG_PRI(pri)) & syslog_mask))
		goto done;

	openlog(NULL, 0, pri & LOG_FACMASK);

	if (!(pri & LOG_FACMASK))
		pri |= syslog_facility;

	GetLocalTime(&stm);
	len = sprintf_s(datagramm, datagramm_size,
		"<%d>%s %2d %02d:%02d:%02d %s %s%s: ",
		pri,
		month[stm.wMonth - 1], stm.wDay, stm.wHour, stm.wMinute, stm.wSecond,
		local_hostname, syslog_ident, syslog_procid_str);
	vsprintf_s(datagramm + len, datagramm_size - len, fmt, ap);
	p = strchr(datagramm, '\n');
	if (p)
		*p = 0;
	p = strchr(datagramm, '\r');
	if (p)
		*p = 0;

	p = datagramm + strlen(datagramm);
	*(p++) = '\r';
	*(p++) = '\n';
	*p = 0;

	OutputDebugStringA(datagramm);

done:
	;
}


#endif