import logging
import pathlib


# ---------------------------------------------------------------------------
# TRACE level (numeric 5, one step below DEBUG=10)
# Registered once at import time so every module that imports logsupport
# can call logger.trace(...) without any additional setup.
# ---------------------------------------------------------------------------

TRACE = 5


def _register_trace_level() -> None:
    """Add the TRACE level and Logger.trace() method if not already present."""
    if hasattr(logging, 'TRACE'):
        return
    logging.TRACE = TRACE                                       # type: ignore[attr-defined]
    logging.addLevelName(TRACE, 'TRACE')

    def trace(self, message, *args, **kwargs):                  # noqa: ANN001
        if self.isEnabledFor(TRACE):
            self._log(TRACE, message, args, **kwargs)           # pylint: disable=protected-access

    logging.Logger.trace = trace                                # type: ignore[attr-defined]


_register_trace_level()


# ---------------------------------------------------------------------------
# Logger factory
# ---------------------------------------------------------------------------

def setup_logger(name='cxlogger', log_file='main.log', level=TRACE,
                 enable_console=True, format_log=True, file_logging=True):
    """
    Create (or retrieve) a named logger.

    Parameters
    ----------
    name          : Logger name; shared across modules via logging.getLogger().
    log_file      : File path used when file_logging=True.
    level         : Minimum level captured by the logger itself (default: TRACE).
    enable_console: Attach a StreamHandler at INFO level.
    format_log    : Apply the standard timestamp/level/message formatter.
    file_logging  : Attach a FileHandler at *level*. Pass False to defer file
                    logging until the run directory is known; call
                    add_file_handler() from main() afterwards.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s') if format_log else None

    # Create file handler only when explicitly requested.
    # The module-level call below passes file_logging=False so no file is opened
    # until the run directory is known and add_file_handler() is called from main().
    if file_logging:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        if formatter:
            file_handler.setFormatter(formatter)

    if enable_console:
        console_handler = logging.StreamHandler()
        # INFO level on the console reduces verbosity while TRACE/DEBUG go to the log file.
        console_handler.setLevel(logging.INFO)
        if formatter:
            console_handler.setFormatter(formatter)

    if not logger.handlers:
        if file_logging:
            logger.addHandler(file_handler)
        if enable_console:
            logger.addHandler(console_handler)

    return logger


def add_file_handler(log_path, name='cxlogger'):
    """
    Add a FileHandler pointing at log_path to the named logger.
    Called once from main() as soon as the run directory is known, so the
    execution log is written directly to the run folder and never to the
    working directory.

    The handler is set to TRACE level so every log record — including
    trace()-level calls — is captured in the file.
    """
    pathlib.Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    log = logging.getLogger(name)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler = logging.FileHandler(log_path)
    handler.setLevel(TRACE)
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.debug(f'File logging started: [{log_path}]')


# ---------------------------------------------------------------------------
# Module-level shared logger (console only).
# File logging is deferred to add_file_handler() in main() once the run
# directory path is resolved, so no log file is created in the working
# directory on import.
# ---------------------------------------------------------------------------

logger = setup_logger(file_logging=False)


def get_logger(name: str = 'cxlogger') -> logging.Logger:
    """
    Return the named logger.  Provided for backward compatibility with
    modules that call ``from logsupport import get_logger``.
    """
    return logging.getLogger(name)
