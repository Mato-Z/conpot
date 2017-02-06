# Copyright (C) 2014  Daniel creo Haslinger <creo-conpot@blackmesa.at>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


import MySQLdb
import gevent
import logging
import json
import re
import subprocess

from warnings import filterwarnings
filterwarnings('ignore', category=MySQLdb.Warning)

logger = logging.getLogger(__name__)


class MySQLlogger(object):

    def __init__(self, host, port, db, username, passphrase, logdevice, logsocket, sensorid):
        self.host = host
        self.port = port
        self.db = db
        self.username = username
        self.passphrase = passphrase
        self.logdevice = logdevice
        self.logsocket = logsocket
        self.sensorid = sensorid

        self._connect()

    def _connect(self):
        try:
            if str(self.logsocket).lower() == 'tcp':
                self.conn = MySQLdb.connect(host=self.host,
                                            port=self.port,
                                            user=self.username,
                                            passwd=self.passphrase,
                                            db=self.db)
                self._create_db()
            elif str(self.logsocket).lower() == 'dev':
                self.conn = MySQLdb.connect(unix_socket=self.logdevice,
                                            user=self.username,
                                            passwd=self.passphrase,
                                            db=self.db)
                self._create_db()
        except (AttributeError, MySQLdb.OperationalError):
            logger.error('Could not create a stable database connection for logging. Check database and credentials.')

    def _create_db(self):
        return True
        # This is useful only when creating the table, that
        # seems to cause problems when the table already exists
        cursor = self.conn.cursor()
        cursor.execute(""" SELECT count(*) FROM information_schema.tables WHERE table_name = %s and table_schema=%s""",("events",self.db)) 
        if (cursor.fetchone()[0]) == 0:
            cursor.execute("""CREATE TABLE IF NOT EXISTS `events` (
                            `id` bigint(20) NOT NULL AUTO_INCREMENT,
                            `sensorid` text NOT NULL,
                            `session` text NOT NULL,
                            `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            `remote` text NOT NULL,
                            `protocol` text NOT NULL,
                            `request` text NOT NULL,
                            `response` text NOT NULL,
                            PRIMARY KEY (`id`)
                            ) ENGINE=InnoDB DEFAULT CHARSET=latin1;
                           """)

    def createEvent(self, cursor, event, asnid, retry=1):
        try:
            if len(event["data"].keys()) > 1:
                cursor.execute("""INSERT INTO
                                    events (sensorid, session, remote, protocol, request, response, asnid)
                                  VALUES
                                    (%s, %s, %s, %s, %s, %s, %s)""", (str(self.sensorid),
                                                                  str(event["id"]),
                                                                  str(event["remote"]),
                                                                  event["data_type"],
                                                                  event["data"].get('request'),
                                                                  event["data"].get('response'),
                                                                  asnid))
            else:
                cursor.execute("""INSERT INTO
                                    events (sensorid, session, remote, protocol,request, response, asnid)
                                  VALUES
                                    (%s, %s, %s, %s, %s,"NA", %s)""", (str(self.sensorid),
                                                                  str(event["id"]),
                                                                  str(event["remote"]),
                                                                  event["data_type"],
                                                                  event["data"].get('type'),
                                                                  asnid))
            self.conn.commit()
        except (AttributeError, MySQLdb.OperationalError):
            self._connect()

            if retry == 0:
                logger.error('Logging failed. Database connection not available.')
                return False
            else:
                logger.debug('Logging failed: Database connection lost. Retrying (%s tries left)...', retry)
                retry -= 1
                gevent.sleep(float(0.5))
                return self.log(event, retry)

        return cursor.lastrowid

    def createEventWithASN(self, cursor, event, retry=1):
        def addslashes(s):
            l = ["\\", '"', "'", "\0", ]
            for i in l:
                if i in s:
                    s = s.replace(i, '\\'+i)
            return s

        def reverseIP(address):
            temp = re.split("\.", address)
            convertedAddress = str(temp[3]) +'.' + str(temp[2]) + '.' + str(temp[1]) +'.' + str(temp[0])
            return convertedAddress

        peerIP = event["remote"][0]
        peerPort = event["remote"][1]
        querycmd1 = reverseIP(peerIP) + '.origin.asn.cymru.com'
        response1 = subprocess.Popen(['dig', '-t', 'TXT', querycmd1, '+short'], stdout=subprocess.PIPE).communicate()[0].decode('utf-8')
        response1List = re.split('\|', response1)
        ASN = response1List[0].strip('" ')
        querycmd2 = 'AS' + ASN + '.asn.cymru.com'
        response2 = subprocess.Popen(['dig', '-t', 'TXT', querycmd2, '+short'], stdout=subprocess.PIPE).communicate()[0].decode('utf-8')
        response2List = re.split('\|', response2)
        if len(response2List) < 4:
            attackid = self.createEvent(cursor, event, 1, retry)
            logger.info("Invalid AS response, attackid = %i" % (attackid))
        else:
            isp = addslashes(response2List[4].replace('"', '').strip('"\' \n'))
            network = addslashes(response1List[1].strip('"\' \n'))
            country = addslashes(response1List[2].strip('"\' \n'))
            registry = addslashes(response1List[3].strip('"\' \n'))
            isp = network + "-" + isp
            cursor.execute("""SELECT `asnid` FROM `asinfo` WHERE `asn` = %s AND `rir` = %s AND `country` = %s AND `asname` = %s """, (ASN, registry, country, isp))
            r = cursor.fetchone()
            if r:
                attackid = self.createEvent(cursor, event, int(r[0]), retry)
                logger.info("Existing AS response (%s,%s,%s,%s), attackid = %i" % (isp, network, country, registry, attackid))
            else:
                r = cursor.execute("""INSERT INTO `asinfo` (`asn`, `rir`, `country`, `asname`) VALUES (%s, %s, %s, %s) """, (ASN, registry, country, isp))
                asnid = cursor.lastrowid
                attackid = self.createEvent(cursor, event, asnid, retry)
                logger.info("New AS response (%s,%s,%s,%s), attackid = %i" % (isp, network, country, registry, attackid))
      
        return attackid


    def log(self, event, retry=1):
        cursor = self.conn.cursor()
        return self.createEventWithASN(cursor, event, retry)

    def log_session(self, session):
        pass

    def select_data(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM events")
        print cursor.fetchall()

    def select_session_data(self, sessionid):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM events WHERE session = %s", [str(sessionid)])
        return cursor.fetchall()

    def truncate_table(self, table):
        cursor = self.conn.cursor()
        try:
            affected = cursor.execute("TRUNCATE TABLE %s", [str(table)])
            self.conn.commit()
        except (AttributeError, MySQLdb.IntegrityError, MySQLdb.OperationalError):
            return False

        return affected
