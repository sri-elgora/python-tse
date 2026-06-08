import os.path
import datetime
import logging
import codecs
from base64 import b64encode
from ctypes import *
from wormtypes import *
from worminfo import Worm_Info
from wormentry import Worm_Entry
from wormtransactionresponse import Worm_Transaction_Response
from wormexception import WormException, WormError_to_exception

log = logging.getLogger('worm')

def find_mountpoint():
    with open('/proc/mounts', 'r') as mounts:
        for line in mounts.readlines():
            dir = line.split(' ')[1]
            if os.path.exists(os.path.join(dir, 'TSE_COMM.DAT')):
                log.info('found TSE unit at %s' % (dir,))
                return dir
    return None


class Worm:
    wormlib = None

    def __init__(self, clientid, mountpoint=None, time_admin_pin=None,
                 library=None, keepalive=None):
        self.qrcode_data = None
        log.setLevel(logging.DEBUG)
        self.time_admin_pin = time_admin_pin
        self.clientid = clientid
        self.entry = None
        self.mountpoint = mountpoint
        self.keepalive = keepalive
        self._autopilot_enabled = False
        self.export_callback = None
        if not library:
            library = os.path.abspath(
                os.path.join(os.path.abspath(os.path.dirname(__file__)),
                             '../../so/libWormAPI.so'))
        if not os.path.exists(library):
            log.critical('cannot find TSE / SMAERS library: %s' % (library,))
            raise WormException(WORM_ERROR_UNKNOWN,
                                'Cannot find TSE / SMAERS library. Was expected as %s' % library)
        log.debug('using TSE / SMAERS library at %s' % library)
        self.wormlib = cdll.LoadLibrary(library)
        self.ctx = WormContext()
        self.entry = Worm_Entry(self)
        self.info = None
        try:
            self.setup()
        except:
            log.error('TSE: Exception occured whilst initializing TSE. Possibly no module present?!')
            pass

    def setup(self, mountpoint=None, keepalive=None):
        if not mountpoint:
            mountpoint = self.mountpoint
        if not mountpoint:
            mountpoint = find_mountpoint()
        if not mountpoint:
            log.error('cannot find TSE unit on any mount path')
            raise WormException(WORM_ERROR_NO_WORM_CARD, 'Cannot find TSE unit!')

        self.wormlib.worm_init.restype = WormError
        self.wormlib.worm_init.argtypes = (POINTER(WormContext), c_char_p)
        log.debug('call worm_init()')
        ret = self.wormlib.worm_init(byref(self.ctx), mountpoint.encode('utf-8'))
        WormError_to_exception(ret)

        try:
            if keepalive and int(keepalive) > 0:
                self.keepalive_configure(keepalive)
            elif keepalive is False or keepalive == 0:
                self.keepalive_disable()
            elif self.keepalive and int(self.keepalive) > 0:
                self.keepalive_configure(self.keepalive)
            else:
                self.keepalive_disable()
        except ValueError:
            log.critical(f'could not understand keepalive argument {str(self.keepalive)}, disabling keepalive')
            self.keepalive_disable()

        self.info = Worm_Info(self)

        if self.info.initializationState == WORM_INIT_DECOMMISSIONED:
            log.critical('this TSE unit is out of order / decommissioned permanently!')
            raise WormException(WORM_ERROR_TSE_DECOMMISSIONED,
                                'TSE ist unwiderruflich außer Betrieb gesetzt!')
        elif self.info.initializationState == WORM_INIT_UNINITIALIZED:
            log.warning('this TSE module is not yet set up! Please initialize!')
            import warnings
            warnings.warn(Warning('TSE ist noch nicht initialisiert. Bitte zuerst initialisieren!'))

    def __del__(self):
        log.debug('TSE library is about to be shut down')
        if self.info:
            del(self.info)
        if self.wormlib:
            self.wormlib.worm_cleanup.restype = WormError
            ret = self.wormlib.worm_cleanup(self.ctx)
            WormError_to_exception(ret)

    ####################################################################
    # Keepalive
    ####################################################################

    def keepalive_configure(self, intervalInSeconds: int):
        assert 1 <= intervalInSeconds <= 3600
        self.wormlib.worm_keepalive_configure.argtypes = (WormContext, c_int)
        self.wormlib.worm_keepalive_configure.restype = WormError
        ret = self.wormlib.worm_keepalive_configure(self.ctx, intervalInSeconds)
        WormError_to_exception(ret)
        return ret

    def keepalive_disable(self):
        self.wormlib.worm_keepalive_disable.argtypes = (WormContext,)
        self.wormlib.worm_keepalive_disable.restype = WormError
        ret = self.wormlib.worm_keepalive_disable(self.ctx)
        WormError_to_exception(ret)
        return ret

    ####################################################################
    # Library Information
    ####################################################################

    def getVersion(self):
        self.wormlib.worm_getVersion.restype = c_char_p
        return self.wormlib.worm_getVersion().decode('latin1')

    def logTimeFormat(self):
        self.wormlib.worm_logTimeFormat.restype = c_char_p
        return self.wormlib.worm_logTimeFormat().decode('latin1')

    def signatureAlgorithm(self):
        self.wormlib.worm_signatureAlgorithm.restype = c_char_p
        return self.wormlib.worm_signatureAlgorithm().decode('latin1')

    ####################################################################
    # Autopilot (SDK v6)
    ####################################################################

    def tse_autopilot_enable(self, adminpin=None):
        '''Aktiviert den Autopiloten des SDK v6.

        Der Autopilot übernimmt automatisch: User-Login, Zeitsynchronisierung.
        Empfohlen für TSE v2.0.0+. Funktioniert auch mit TSE v1.
        adminpin kann str oder bytes sein.
        '''
        if not adminpin:
            adminpin = self.time_admin_pin  # Fallback
        if not adminpin:
            raise WormException(WORM_ERROR_INVALID_PARAMETER,
                                'Admin-PIN für Autopilot erforderlich')
        if type(adminpin) == str:
            adminpin = adminpin.encode('latin1')
        self.wormlib.worm_tse_autopilot_enable.argtypes = (WormContext, c_char_p, c_int)
        self.wormlib.worm_tse_autopilot_enable.restype = WormError
        ret = self.wormlib.worm_tse_autopilot_enable(self.ctx, adminpin, len(adminpin))
        WormError_to_exception(ret)
        self._autopilot_enabled = True
        log.info('TSE Autopilot aktiviert')
        return ret

    def tse_autopilot_disable(self):
        self.wormlib.worm_tse_autopilot_disable.argtypes = (WormContext,)
        self.wormlib.worm_tse_autopilot_disable.restype = WormError
        ret = self.wormlib.worm_tse_autopilot_disable(self.ctx)
        WormError_to_exception(ret)
        self._autopilot_enabled = False
        log.info('TSE Autopilot deaktiviert')
        return ret

    ####################################################################
    # TSE-Configuration
    ####################################################################

    def tse_factoryReset(self):
        self.wormlib.worm_tse_factoryReset.restype = WormError
        self.wormlib.worm_tse_factoryReset.argtypes = (WormContext,)
        ret = self.wormlib.worm_tse_factoryReset(self.ctx)
        WormError_to_exception(ret)
        self.info.update()
        return ret

    def tse_needs_setup(self):
        '''Gibt True zurück wenn die TSE noch eingerichtet werden muss (SDK v6).'''
        needs_setup = c_int(0)
        self.wormlib.worm_tse_needs_setup.argtypes = (WormContext, POINTER(c_int))
        self.wormlib.worm_tse_needs_setup.restype = WormError
        ret = self.wormlib.worm_tse_needs_setup(self.ctx, byref(needs_setup))
        WormError_to_exception(ret)
        return bool(needs_setup.value)

    def tse_startup(self, adminpin=None, enable_autopilot=False):
        '''Bringt eine bereits eingerichtete TSE in den transaktionsbereiten Zustand (SDK v6).

        Führt durch: Selbsttest + Zeitsynchronisierung + optional Autopilot.
        Setzt voraus, dass tse_setup() oder tse_setup_ext() bereits aufgerufen wurde.
        '''
        if not adminpin:
            adminpin = self.time_admin_pin
        if not adminpin:
            raise WormException(WORM_ERROR_INVALID_PARAMETER,
                                'Admin-PIN für tse_startup() erforderlich')
        if type(adminpin) == str:
            adminpin = adminpin.encode('latin1')
        self.wormlib.worm_tse_startup.argtypes = (WormContext, c_char_p, c_char_p, c_int, c_int)
        self.wormlib.worm_tse_startup.restype = WormError
        ret = self.wormlib.worm_tse_startup(
            self.ctx,
            self.clientid.encode('latin1'),
            adminpin, len(adminpin),
            int(enable_autopilot)
        )
        WormError_to_exception(ret)
        self._autopilot_enabled = enable_autopilot
        self.info.update()
        log.info('TSE startup abgeschlossen (autopilot=%s)', enable_autopilot)
        return ret

    def tse_prepare(self, adminpuk, adminpin, time_admin_pin=None):
        '''Kümmert sich beim Programmstart um tse_setup() bei Bedarf oder richtet die
        clientid ein. Nutzt SDK v6 Helpers wenn verfügbar.'''
        if not time_admin_pin:
            time_admin_pin = self.time_admin_pin
        if not self.info:
            self.setup()
        if self.info.initializationState == WORM_INIT_UNINITIALIZED:
            log.warning('TSE still not commissioned, calling tse_setup_ext()')
            self.tse_setup_ext(adminpuk, adminpin, time_admin_pin, enable_autopilot=True)
        else:
            # TSE bereits eingerichtet – startup helper verwenden
            try:
                self.tse_startup(adminpin, enable_autopilot=True)
            except WormException as e:
                # Fallback für ältere SDK-Versionen ohne worm_tse_startup
                log.warning('tse_startup() nicht verfügbar, nutze Legacy-Pfad: %s', e.message)
                if not self.info.hasPassedSelfTest:
                    try:
                        self.tse_runSelfTest()
                    except WormException as e2:
                        if e2.errno == WORM_ERROR_CLIENT_NOT_REGISTERED:
                            self.user_login(WORM_USER_ADMIN, adminpin)
                            self.tse_registerClient(adminpin=adminpin)
                            self.user_logout(WORM_USER_ADMIN)
                        self.tse_runSelfTest()
                if not self.info.hasValidTime:
                    self.tse_updateTime()

    def tse_setup(self, adminpuk, adminpin, timeadminpin):
        '''Einmalige Initialisierung der TSE (Legacy-Methode, identisch mit SDK-Verhalten).'''
        if self.info.initializationState == WORM_INIT_INITIALIZED:
            raise WormException(WORM_ERROR_TSE_ALREADY_INITIALIZED,
                                'TSE-Initialisierung ist schon erfolgt!')
        credentialseed = b'SwissbitSwissbit'
        if type(adminpuk) == str:
            adminpuk = adminpuk.encode('latin1')
        if len(adminpuk) != 6:
            raise ValueError('Admin-PUK muss genau 6 Stellen lang sein')
        if type(adminpin) == str:
            adminpin = adminpin.encode('latin1')
        if len(adminpin) != 5:
            raise ValueError('Admin-PIN muss genau 5 Stellen lang sein')
        if type(timeadminpin) == str:
            timeadminpin = timeadminpin.encode('latin1')
        if len(timeadminpin) != 5:
            raise ValueError('Time-Admin-PIN muss genau 5 Stellen lang sein')
        self.wormlib.worm_tse_setup.restype = WormError
        self.wormlib.worm_tse_setup.argtypes = (
            WormContext, c_char_p, c_int, c_char_p, c_int,
            c_char_p, c_int, c_char_p, c_int, c_char_p)
        ret = self.wormlib.worm_tse_setup(
            self.ctx, credentialseed, len(credentialseed),
            adminpuk, len(adminpuk), adminpin, len(adminpin),
            timeadminpin, len(timeadminpin),
            self.clientid.encode('latin1'))
        WormError_to_exception(ret)
        self.info.update()
        return ret

    def tse_setup_ext(self, adminpuk, adminpin, timeadminpin, enable_autopilot=False):
        '''SDK v6: Erweiterte Initialisierung inkl. Zeitsynchronisierung + optionaler Autopilot.

        Für TSE v2 empfohlen. Funktioniert auch mit TSE v1.
        Nach erfolgreichem Aufruf ist die TSE sofort transaktionsbereit.
        '''
        if self.info.initializationState == WORM_INIT_INITIALIZED:
            raise WormException(WORM_ERROR_TSE_ALREADY_INITIALIZED,
                                'TSE-Initialisierung ist schon erfolgt!')
        credentialseed = b'SwissbitSwissbit'
        if type(adminpuk) == str:
            adminpuk = adminpuk.encode('latin1')
        if len(adminpuk) != 6:
            raise ValueError('Admin-PUK muss genau 6 Stellen lang sein')
        if type(adminpin) == str:
            adminpin = adminpin.encode('latin1')
        if len(adminpin) != 5:
            raise ValueError('Admin-PIN muss genau 5 Stellen lang sein')
        if type(timeadminpin) == str:
            timeadminpin = timeadminpin.encode('latin1')
        if len(timeadminpin) != 5:
            raise ValueError('Time-Admin-PIN muss genau 5 Stellen lang sein')
        self.wormlib.worm_tse_setup_ext.restype = WormError
        self.wormlib.worm_tse_setup_ext.argtypes = (
            WormContext, c_char_p, c_int, c_char_p, c_int,
            c_char_p, c_int, c_char_p, c_int, c_char_p, c_int)
        ret = self.wormlib.worm_tse_setup_ext(
            self.ctx, credentialseed, len(credentialseed),
            adminpuk, len(adminpuk), adminpin, len(adminpin),
            timeadminpin, len(timeadminpin),
            self.clientid.encode('latin1'),
            int(enable_autopilot))
        WormError_to_exception(ret)
        self._autopilot_enabled = enable_autopilot
        self.info.update()
        log.info('TSE setup_ext abgeschlossen (autopilot=%s)', enable_autopilot)
        return ret

    def tse_runSelfTest(self):
        self.wormlib.worm_tse_runSelfTest.argtypes = (WormContext, c_char_p)
        self.wormlib.worm_tse_runSelfTest.restype = WormError
        ret = self.wormlib.worm_tse_runSelfTest(self.ctx, self.clientid.encode('latin1'))
        WormError_to_exception(ret)
        self.info.update()
        return ret

    def tse_updateTime(self):
        if self.time_admin_pin and not self._autopilot_enabled:
            self.user_login(WORM_USER_TIME_ADMIN, self.time_admin_pin)
        self.wormlib.worm_tse_updateTime.argtypes = (WormContext, worm_uint)
        self.wormlib.worm_tse_updateTime.restype = WormError
        ret = self.wormlib.worm_tse_updateTime(
            self.ctx, int(datetime.datetime.now().timestamp()))
        WormError_to_exception(ret)
        self.info.update()
        return ret

    def tse_listRegisteredClients(self):
        skip = 0
        clients = []
        while True:
            _clients = WormRegisteredClients()
            self.wormlib.worm_tse_listRegisteredClients.argtypes = (
                WormContext, c_int, POINTER(WormRegisteredClients))
            ret = self.wormlib.worm_tse_listRegisteredClients(self.ctx, skip, _clients)
            WormError_to_exception(ret)
            data = False
            for entry in _clients.clientIds:
                id = cast(entry, c_char_p).value.decode('latin1')
                if id:
                    clients.append(id)
                    data = True
            if len(clients) >= _clients.amount or not data:
                break
            skip += 16
        return clients

    def tse_registerClient(self, clientid=None, adminpin=None):
        if not clientid:
            clientid = self.clientid
        if adminpin and not self._autopilot_enabled:
            self.user_login(WORM_USER_ADMIN, adminpin)
        self.wormlib.worm_tse_registerClient.argtypes = (WormContext, c_char_p)
        ret = self.wormlib.worm_tse_registerClient(self.ctx, clientid.encode('latin1'))
        WormError_to_exception(ret)

    def tse_deregisterClient(self, clientid=None):
        if not clientid:
            clientid = self.clientid
        self.wormlib.worm_tse_deregisterClient.argtypes = (WormContext, c_char_p)
        ret = self.wormlib.worm_tse_deregisterClient(self.ctx, clientid.encode('latin1'))
        WormError_to_exception(ret)

    ####################################################################
    # User-Management
    ####################################################################

    def user_login(self, userid, pin):
        if type(pin) == str:
            pin = pin.encode('latin1')
        remainingRetries = c_int()
        self.wormlib.worm_user_login.argtypes = (WormContext, c_int, c_char_p, c_int, POINTER(c_int))
        self.wormlib.worm_user_login.restype = WormError
        ret = self.wormlib.worm_user_login(
            self.ctx, userid, pin, len(pin), byref(remainingRetries))
        WormError_to_exception(ret)
        self.info.update()
        return remainingRetries.value

    def user_logout(self, userid=None):
        # In TSE v2 wird userid ignoriert – immer der aktuelle Benutzer
        self.wormlib.worm_user_logout.argtypes = (WormContext, c_int)
        self.wormlib.worm_user_logout.restype = WormError
        ret = self.wormlib.worm_user_logout(self.ctx, userid if userid is not None else 0)
        WormError_to_exception(ret)
        self.info.update()

    def user_change_pin(self, userid, old_pin, new_pin):
        if type(old_pin) == str:
            old_pin = old_pin.encode('latin1')
        if type(new_pin) == str:
            new_pin = new_pin.encode('latin1')
        self.wormlib.worm_user_change_pin.argtypes = (
            WormContext, c_int, c_char_p, c_int, c_char_p, c_int)
        self.wormlib.worm_user_change_pin.restype = WormError
        ret = self.wormlib.worm_user_change_pin(
            self.ctx, userid, old_pin, len(old_pin), new_pin, len(new_pin))
        WormError_to_exception(ret)

    def user_unblock(self, userid, puk, new_pin):
        if type(puk) == str:
            puk = puk.encode('latin1')
        if type(new_pin) == str:
            new_pin = new_pin.encode('latin1')
        remainingRetries = c_int()
        self.wormlib.worm_user_unblock.argtypes = (
            WormContext, c_int, c_char_p, c_int, c_char_p, c_int, POINTER(c_int))
        self.wormlib.worm_user_unblock.restype = WormError
        ret = self.wormlib.worm_user_unblock(
            self.ctx, userid, puk, len(puk), new_pin, len(new_pin),
            byref(remainingRetries))
        WormError_to_exception(ret)
        return remainingRetries.value

    def user_deriveInitialCredentials(self):
        seed = b'SwissbitSwissbit'
        adminpuk = c_char_p(b'xxxxxx')
        adminpin = c_char_p(b'xxxxx')
        timeadminpin = c_char_p(b'xxxxx')
        self.wormlib.worm_user_deriveInitialCredentials.argtypes = (
            WormContext, c_char_p, c_int, c_char_p, c_int, c_char_p, c_int, c_char_p, c_int)
        self.wormlib.worm_user_deriveInitialCredentials.restype = WormError
        ret = self.wormlib.worm_user_deriveInitialCredentials(
            self.ctx, seed, len(seed), adminpuk, 6, adminpin, 5, timeadminpin, 5)
        WormError_to_exception(ret)
        return (adminpuk.value.decode('latin1'),
                adminpin.value.decode('latin1'),
                timeadminpin.value.decode('latin1'))

    ####################################################################
    # Transactions
    ####################################################################

    def __pre_transaction_checks(self):
        if not self.info:
            raise WormException(WORM_ERROR_NO_WORM_CARD, 'No TSE available')
        self.info.update()
        # TSE v2 führt Selbsttest automatisch aus; für v1 manuell prüfen
        if not self.info.hasPassedSelfTest and not self.info.isTSEv2:
            self.tse_runSelfTest()
        # Zeitsync: wird bei Autopilot automatisch erledigt
        if not self.info.hasValidTime and not self._autopilot_enabled:
            self.tse_updateTime()
        if not self.info.isCtssInterfaceActive:
            raise WormException(WORM_ERROR_WRONG_STATE_NEEDS_ACTIVE_CTSS, 'TSE not ready!')

    def transaction_start(self, processdata, processtype):
        self.__pre_transaction_checks()
        if type(processdata) == str:
            processdata = processdata.encode('utf-8')
        if type(processtype) == str:
            processtype = processtype.encode('utf-8')
        r = Worm_Transaction_Response(self)
        self.wormlib.worm_transaction_start.argtypes = (
            WormContext, c_char_p, c_char_p, c_int64, c_char_p, WormTransactionResponse)
        self.wormlib.worm_transaction_start.restype = WormError
        ret = self.wormlib.worm_transaction_start(
            self.ctx, self.clientid.encode('latin1'),
            processdata, len(processdata), processtype, r.response)
        WormError_to_exception(ret)
        self.transaction_start_time = r.logTime
        return r

    def transaction_update(self, transactionnumber, processdata, processtype):
        self.__pre_transaction_checks()
        if type(processdata) == str:
            processdata = processdata.encode('utf-8')
        if type(processtype) == str:
            processtype = processtype.encode('utf-8')
        r = Worm_Transaction_Response(self)
        self.wormlib.worm_transaction_update.argtypes = (
            WormContext, c_char_p, worm_uint, c_char_p, worm_uint, c_char_p, WormTransactionResponse)
        self.wormlib.worm_transaction_update.restype = WormError
        ret = self.wormlib.worm_transaction_update(
            self.ctx, self.clientid.encode('latin1'),
            transactionnumber, processdata, len(processdata), processtype, r.response)
        WormError_to_exception(ret)
        return r

    def transaction_finish(self, transactionnumber, processdata, processtype):
        self.__pre_transaction_checks()
        if type(processdata) == str:
            processdata = processdata.encode('utf-8')
        if type(processtype) == str:
            processtype = processtype.encode('utf-8')
        r = Worm_Transaction_Response(self)
        self.wormlib.worm_transaction_finish.argtypes = (
            WormContext, c_char_p, worm_uint, c_char_p, worm_uint, c_char_p, WormTransactionResponse)
        self.wormlib.worm_transaction_finish.restype = WormError
        ret = self.wormlib.worm_transaction_finish(
            self.ctx, self.clientid.encode('latin1'),
            transactionnumber, processdata, len(processdata), processtype, r.response)
        WormError_to_exception(ret)
        self.info.update()

        qrcode = ['V0']
        qrcode.append(self.clientid)
        qrcode.append(processtype.decode('utf-8'))
        qrcode.append(processdata.decode('utf-8'))
        qrcode.append(r.transactionNumber)
        qrcode.append(r.signatureCounter)
        qrcode.append(self.transaction_start_time.astimezone(
            datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z'))
        qrcode.append(r.logTime.astimezone(
            datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z'))
        qrcode.append(self.signatureAlgorithm())
        qrcode.append('unixTime')
        qrcode.append(b64encode(r.signature).decode('ascii').strip())
        qrcode.append(b64encode(self.info.tsePublicKey).decode('ascii').strip())
        self.qrcode_data = ';'.join([str(x) for x in qrcode])

        return r

    def transaction_listStartedTransactions(self, skip=0):
        self.__pre_transaction_checks()
        numbers_buffer = (worm_uint * 62)()
        count = c_int()
        self.wormlib.worm_transaction_listStartedTransactions.argtypes = (
            WormContext, c_char_p, c_uint, worm_uint * 62, c_int, POINTER(c_int))
        self.wormlib.worm_transaction_listStartedTransactions.restype = WormError
        ret = self.wormlib.worm_transaction_listStartedTransactions(
            self.ctx, self.clientid.encode('latin1'), skip,
            numbers_buffer, 62, byref(count))
        WormError_to_exception(ret)
        return numbers_buffer[:count.value]

    ####################################################################
    # Export
    ####################################################################

    def getLogMessageCertificate(self):
        sLength = c_uint32()
        self.wormlib.worm_getLogMessageCertificate.argtypes = (
            WormContext, POINTER(c_char_p), POINTER(c_uint32))
        self.wormlib.worm_getLogMessageCertificate(self.ctx, None, byref(sLength))
        buffer = pointer((c_char * sLength.value)())
        self.wormlib.worm_getLogMessageCertificate.argtypes = (
            WormContext, POINTER(c_char * sLength.value), POINTER(c_uint32))
        self.wormlib.worm_getLogMessageCertificate(self.ctx, buffer, byref(sLength))
        s = cast(buffer, POINTER(c_char))
        return string_at(s, size=sLength.value)

    def export_tar(self, filename, clientid=None, time_start=None, time_end=None,
                   trxid_start=None, trxid_end=None):
        CALLBACK = CFUNCTYPE(c_int, POINTER(c_char), c_uint, c_void_p)
        callback = CALLBACK(self.export_tar_callback)
        with open(filename, 'wb') as self.tarfile:
            if time_start:
                if type(time_start) == datetime.datetime:
                    time_start = int(time_start.timestamp())
                    time_end = int(time_end.timestamp())
                ret = self.wormlib.worm_export_tar_filtered_time(
                    self.ctx, worm_uint(time_start), worm_uint(time_end),
                    c_char_p(clientid), callback, None)
                WormError_to_exception(ret)
            elif trxid_start:
                ret = self.wormlib.worm_export_tar_filtered_transaction(
                    self.ctx, worm_uint(trxid_start), worm_uint(trxid_end),
                    c_char_p(clientid), callback, None)
                WormError_to_exception(ret)
            else:
                ret = self.wormlib.worm_export_tar(self.ctx, callback, None)
                WormError_to_exception(ret)

    def export_tar_incremental(self, filename, lastState=None, callback=None):
        (first, last, state, _) = self.export_tar_incremental_ex(
            filename, lastState=lastState, maxExportSize=0, callback=callback)
        return (first, last, state)

    def export_tar_incremental_ex(self, filename, lastState=None,
                                   maxExportSize=0, callback=None):
        self.export_callback = callback
        CALLBACK = CFUNCTYPE(c_int, POINTER(c_char), c_uint, c_uint32, c_uint32, c_void_p)
        cb = CALLBACK(self.export_tar_incremental_callback)
        with open(filename, 'wb') as self.tarfile:
            firstSignatureCounter = c_uint64()
            lastSignatureCounter = c_uint64()
            last_state = c_char_p(lastState) if lastState else None
            last_state_len = c_int(len(lastState)) if lastState else c_int(0)
            new_state = cast(create_string_buffer(WORM_EXPORT_TAR_INCREMENTAL_STATE_SIZE), c_char_p)
            new_state_len = c_int(WORM_EXPORT_TAR_INCREMENTAL_STATE_SIZE)
            maxExportSize = c_uint64(maxExportSize)
            allDataExported = c_int64()
            ret = self.wormlib.worm_export_tar_incremental_ex(
                self.ctx, last_state, last_state_len, new_state, new_state_len,
                maxExportSize, byref(allDataExported),
                byref(firstSignatureCounter), byref(lastSignatureCounter), cb, None)
            WormError_to_exception(ret)
            new_state = cast(new_state, POINTER(c_char))
            return_state = string_at(new_state, new_state_len)
            self.export_callback = None
            return (firstSignatureCounter.value, lastSignatureCounter.value,
                    return_state, bool(allDataExported))

    def export_tar_incremental_sizeInSectors(self, lastState=None):
        last_state = c_char_p(lastState) if lastState else None
        last_state_len = c_int(len(lastState)) if lastState else c_int(0)
        size = c_uint64()
        ret = self.wormlib.worm_export_tar_incremental_sizeInSectors(
            self.ctx, last_state, last_state_len, byref(size))
        WormError_to_exception(ret)
        return size.value

    def export_tar_incremental_size(self, lastState=None):
        last_state = c_char_p(lastState) if lastState else None
        last_state_len = c_int(len(lastState)) if lastState else c_int(0)
        size = c_uint64()
        ret = self.wormlib.worm_export_tar_incremental_size(
            self.ctx, last_state, last_state_len, byref(size))
        WormError_to_exception(ret)
        return size.value

    def export_tar_callback(self, chunk, chunklen, _data):
        chunk = cast(chunk, POINTER(c_char))
        if not self.tarfile:
            return 1
        self.tarfile.write(string_at(chunk, chunklen))
        return 0

    def export_tar_incremental_callback(self, chunk, chunklen, processedBlocks, totalBlocks, _data):
        chunk = cast(chunk, POINTER(c_char))
        if not self.tarfile:
            return 1
        self.tarfile.write(string_at(chunk, chunklen))
        log.info('exported %i / %i blocks' % (processedBlocks, totalBlocks))
        if self.export_callback:
            if not self.export_callback(processedBlocks, totalBlocks):
                return 1
        return 0

    ####################################################################
    # Flash Health
    ####################################################################

    def flash_health_summary(self):
        uncorrectableEccErrors = c_uint32()
        percentageRemainingSpareBlocks = c_uint8()
        percentageRemainingEraseCounts = c_uint8()
        percentageRemainingTenYearsDataRetention = c_uint8()
        self.wormlib.worm_flash_health_summary.argtypes = (
            WormContext, POINTER(c_uint32), POINTER(c_uint8),
            POINTER(c_uint8), POINTER(c_uint8))
        self.wormlib.worm_flash_health_summary.restype = WormError
        ret = self.wormlib.worm_flash_health_summary(
            self.ctx,
            byref(uncorrectableEccErrors),
            byref(percentageRemainingSpareBlocks),
            byref(percentageRemainingEraseCounts),
            byref(percentageRemainingTenYearsDataRetention))
        WormError_to_exception(ret)
        return {
            'uncorrectableEccErrors': uncorrectableEccErrors.value,
            'percentageRemainingSpareBlocks': percentageRemainingSpareBlocks.value,
            'percentageRemainingEraseCounts': percentageRemainingEraseCounts.value,
            'percentageRemainingTenYearsDataRetention': percentageRemainingTenYearsDataRetention.value,
        }

    def flash_health_needs_replacement(self):
        data = self.flash_health_summary()
        self.wormlib.worm_flash_health_needs_replacement.argtypes = (
            c_uint32, c_uint8, c_uint8)
        self.wormlib.worm_flash_health_needs_replacement.restype = c_int
        return bool(self.wormlib.worm_flash_health_needs_replacement(
            data['uncorrectableEccErrors'],
            data['percentageRemainingSpareBlocks'],
            data['percentageRemainingEraseCounts']))
