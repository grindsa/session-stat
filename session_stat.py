#!/usr/bin/python
""" prototyp to dump the session form a pcap file into either XLS or CSV format """
from __future__ import print_function
import sys
import argparse
import os.path
import time
import datetime

try:
    import pyshark
except:
    print('pyshark packages is missing and must be installed via pip....')
    sys.exit(0)

CSV_EXPORT = False
try:
    import xlsxwriter
except:
    print('xlswrite package is missing. data will be exported in csv format only')
    CSV_EXPORT = True

def arg_parse():
    """ collect arguments and command line options
    args:
        None

    returns:
        dictionary containing all configuration options
    """
    config_dic = {}

    parser = argparse.ArgumentParser(description='session analyzer')
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument('-b', dest='DIRECTORY', help='directory with pcap files to analyze')
    grp.add_argument('-r', dest='FILE', help='pcap file to analyze')
    parser.add_argument('-w', dest='OUTPUT_FILE', help='output file', required=True)
    parser.add_argument('-a', '--aggregate', help='aggregate sessions based on src,dst,proto and dst_port', action="store_true")
    parser.add_argument('-c', '--csv', dest='csv', help='export as csv', action="store_true")
    parser.add_argument('-d', '--debug', help='debug mode', action="store_true")
    parser.add_argument('-e', '--expert', help='add information from TCP sequence analysis', action="store_true")
    parser.add_argument('-s', '--sort-by', dest='sort_by', help='sort results by vlan, src, dst, dst_port, cnt or bytes, (default: by time)', required=False)

    args = parser.parse_args()

    if args.FILE:
        if os.path.exists(args.FILE):
            config_dic['file'] = args.FILE
        else:
            print('File \'{0}\' could not be found. Aborting...'.format(args.FILE))
            sys.exit(0)
    elif args.DIRECTORY:
        if os.path.isdir(args.DIRECTORY):
            config_dic['directory'] = args.DIRECTORY
        else:
            print('Directory \'{0}\' could not be found. Aborting...'.format(args.DIRECTORY))
            sys.exit(0)

    config_dic['output_file'] = args.OUTPUT_FILE

    if args.csv:
        config_dic['csv_export'] = args.csv

    if args.aggregate:
        config_dic['aggregate'] = args.aggregate

    if args.sort_by:
        allowed_criteria = ['start', 'src', 'dst', 'vlan', 'proto', 'dst_port', 'cnt', 'bytes']

        config_dic['sort_by'] = []

        key_list = args.sort_by.split(',')
        for k in key_list:
            k = k.rstrip()
            k = k.lstrip()
            if k in allowed_criteria:
                config_dic['sort_by'].append(k)
            else:
                print('Wrong search criteria. Alled criterias are: {0} only...'.format(', '.join(allowed_criteria)))
                sys.exit(0)

    if args.debug:
        config_dic['debug'] = args.debug

    if args.expert:
        config_dic['expert'] = args.expert

    return config_dic

def print_out(debug, text):
    """ print a text if debug flag is set
    args:
       debug - debug flag (1 or 0)
       text  - text to print

    returns:
        None
    """
    if debug == 1:
        print(text)

def key_sorter(dic):
    """ anchor function for sort_dic

    args:
        dic - dicutionary

    returns:
        out_list - list of keys
    """
    out_list = []
    for anchor in SORT_BY:
        out_list.append(dic[1][anchor])

    return out_list

def sort_dic(dic, value, reverse):
    """ sort a nested dictionary by a value

    args:
        dic - dictionary
        value - value to use for sorting
        revers - acending or decending

    returns:
        sort_list - sorted list of keys to be used print dictionary
    """
    global SORT_BY
    SORT_BY = value

    sort_list = []
    for key, val in sorted(dic.iteritems(), key=key_sorter, reverse=reverse):
        sort_list.append(key)

    return sort_list

def create_csv(uts, slist, dic, fname, expert_list, aggregate):
    """ creates an csv file out of the collectd information
    args:
        uts         - unix time stamp
        slist       - sort list
        dic         - dictionary containing the data to insert
        fname       - filename
        expert_list - expert list information from pcap
        aggregate   - aggregate information

    returns:
        None
    """
    with open(fname, 'w') as ofile:

        headline = 'time,src,dst,proto,src_port,dst_port,packets,bytes,duration'
        for expert in expert_list:
            headline = '{0},{1}'.format(headline, expert)

        headline = headline + '\n'
        ofile.write(headline)

        for session in slist:

            proto = ''
            if 'proto' in dic[session]:
                proto = dic[session]['proto']
            line = '{0},{1},{2},{3}'.format(dic[session]['start'], dic[session]['src'], dic[session]['dst'], proto)

            if aggregate:
                if 'src_port_lo' in dic[session] and 'src_port_hi' in dic[session]:
                    if dic[session]['src_port_lo'] == dic[session]['src_port_hi']:
                        line = '{0},{1}'.format(line, dic[session]['src_port_lo'])
                    else:
                        line = '{0},{1} - {2}'.format(line, dic[session]['src_port_lo'], dic[session]['src_port_hi'])
                else:
                    line = '{0},{1}'.format(line, '')
            else:
                if 'src_port' in dic[session]:
                    line = '{0},{1}'.format(line, dic[session]['src_port'])
                else:
                    line = '{0},{1}'.format(line, '')

            if 'dst_port' in dic[session]:
                line = '{0},{1}'.format(line, dic[session]['dst_port'])
            else:
                line = '{0},{1}'.format(line, '')

            if 'cnt' in dic[session]:
                line = '{0},{1}'.format(line, dic[session]['cnt'])
            else:
                line = '{0},{1}'.format(line, '')

            if 'bytes' in dic[session]:
                line = '{0},{1}'.format(line, dic[session]['cnt'])
            else:
                line = '{0},{1}'.format(line, '')

            if 'end' in dic[session]:
                line = '{0},{1}'.format(line, float(dic[session]['end']) - float(dic[session]['start']))
            else:
                line = '{0},{1}'.format(line, '')

            if 'expert' in dic[session]:
                for expert in expert_list:
                    if expert in dic[session]['expert']:
                        line = '{0},{1}'.format(line, dic[session]['expert'][expert])
                    else:
                        line = '{0},{1}'.format(line, '')

            line = line + '\n'
            ofile.write(line)


def create_xlsx(uts, slist, dic, fname, expert_list, aggregate):
    """ creates an excel file out of the collectd information
    args:
        uts         - unix time stamp
        slist        - sort list
        dic         - dictionary containing the data to insert
        fname           - filename
        expert_list - expert list information from pcap
        aggregate   - aggregate information

    returns:
        None
    """
    workbook = xlsxwriter.Workbook('{0}'.format(fname))
    sheet = workbook.add_worksheet(datetime.datetime.fromtimestamp(uts).strftime('%d.%m.%Y %H-%M'))

    row = 1

    # add some formats
    f_headline = workbook.add_format({'bold': True, 'bg_color': '#e64a19', 'font_size': 14, 'font_color': '#ffffff'})
    f_tabhead = workbook.add_format({'bold': True, 'bg_color': '#000000', 'font_color': '#ffffff'})
    f_tabhead.set_text_wrap()
    # f_warning = workbook.add_format({'bg_color': '#ffeb9c',})
    # f_error = workbook.add_format({'bg_color': '#ffc7ce',})
    f_second = workbook.add_format({'bg_color': '#f2f2f2',})

    # column width
    sheet.set_column('A:A', 20)
    sheet.set_column('B:B', 0)
    sheet.set_column('C:D', 15)
    sheet.set_column('E:E', 5)
    # hide session duration column
    sheet.set_column('J:J', 0)
    sheet.set_column('K:K', 2)

    # source-port colum must have a greater width in case of aggregation
    if aggregate:
        sheet.set_column('F:F', 12)

    # add headline
    sheet.merge_range('A1:J1', 'PCAP Analyse: {0}'.format(fname), f_headline)

    # write table headline
    sheet.write(row, 0, 'time', f_tabhead)
    sheet.write(row, 1, 'vlan', f_tabhead)
    sheet.write(row, 2, 'src', f_tabhead)
    sheet.write(row, 3, 'dst', f_tabhead)
    sheet.write(row, 4, 'proto', f_tabhead)
    sheet.write(row, 5, 'src_port', f_tabhead)
    sheet.write(row, 6, 'dst_port', f_tabhead)
    sheet.write(row, 7, 'packets', f_tabhead)
    sheet.write(row, 8, 'bytes', f_tabhead)
    sheet.write(row, 9, 'duration', f_tabhead)

    col = 10
    for expert in expert_list:
        col += 1
        sheet.write(row, col, expert, f_tabhead)

    for session in slist:
        row += 1

        if dic[session]['vlan'] != None:
            sheet.set_column('B:B', 8)

        c_format = None
        if row % 2 == 0:
            c_format = f_second

        sheet.write(row, 0, dic[session]['start'], c_format)
        sheet.write(row, 1, dic[session]['vlan'], c_format)
        sheet.write(row, 2, dic[session]['src'], c_format)
        sheet.write(row, 3, dic[session]['dst'], c_format)
        if 'proto' in dic[session]:
            sheet.write(row, 4, dic[session]['proto'], c_format)
        else:
            sheet.write(row, 4, '', c_format)

        if aggregate:
            if 'src_port_lo' in dic[session] and 'src_port_hi' in dic[session]:
                if dic[session]['src_port_lo'] == dic[session]['src_port_hi']:
                    sheet.write(row, 5, dic[session]['src_port_lo'], c_format)
                else:
                    sheet.write(row, 5, '{0} - {1}'.format(dic[session]['src_port_lo'], dic[session]['src_port_hi']), c_format)
            else:
                sheet.write(row, 5, '', c_format)

        else:
            if 'src_port' in dic[session]:
                sheet.write(row, 6, dic[session]['src_port'], c_format)
            else:
                sheet.write(row, 6, '', c_format)

        if 'dst_port' in dic[session]:
            sheet.write(row, 6, dic[session]['dst_port'], c_format)
        else:
            sheet.write(row, 6, '', c_format)

        if 'cnt' in dic[session]:
            sheet.write(row, 7, dic[session]['cnt'], c_format)
        else:
            sheet.write(row, 7, '', c_format)

        if 'bytes' in dic[session]:
            sheet.write(row, 8, dic[session]['bytes'], c_format)
        else:
            sheet.write(row, 8, '', c_format)

        if 'end' in dic[session]:
            sheet.write(row, 9, float(dic[session]['end']) - float(dic[session]['start']), c_format)
        else:
            sheet.write(row, 9, 0, c_format)

        col = 10
        if 'expert' in dic[session]:
            for expert in expert_list:
                col += 1
                if expert in dic[session]['expert']:
                    sheet.write(row, col, dic[session]['expert'][expert], c_format)
                else:
                    sheet.write(row, col, '', c_format)

    sheet.freeze_panes(2, 10)

    # autofilter
    cell_filter = 'B2:C'+str(row)
    # cell_filter = 'C2:C'+str(row)
    sheet.autofilter(cell_filter)
    workbook.close()

class PcapHelper(object):
    """ class for pcap processing """

    def align_session(self, src, dst, src_port, dst_port):
        """ revert source and dst port in case src is lower than dst """
        if src_port < dst_port:
            return(dst, src, dst_port, src_port)
        else:
            return(src, dst, src_port, dst_port)

    def read_dir(self, directory, aggregate, p_expert):
        """ read directory and parse all pcaps """
        flist = os.listdir(directory)
        for pfile in flist:
            self.read_pcap('{0}/{1}'.format(directory, pfile), aggregate, p_expert)

    def read_pcap(self, pfile, aggregate, p_expert):
        """ read pcap and packet metadata
            store informaition in a dictionary
        """
        print_out(DEBUG, 'open {0}'.format(pfile))
        cap = pyshark.FileCapture(pfile)
        for pkt in cap:
            (tstamp, length, vlan, src, dst, proto, src_port, dst_port, expert) = self.pkt_meta_data(pkt, p_expert)
            self.store_into_dic(tstamp, length, vlan, src, dst, proto, src_port, dst_port, expert, aggregate)

    def store_into_dic(self, tstamp, length, vlan, src, dst, proto, src_port, dst_port, expert, aggregate):
        """ store packet meta data into a global dictionary """
        if(src and dst):
            if aggregate:
                session_identifier = '{0}:{1}:{2}:{3}:{4}'.format(vlan, src, dst, proto, dst_port)
            else:
                session_identifier = '{0}:{1}:{2}:{3}:{4}:{5}'.format(vlan, src, dst, proto, src_port, dst_port)

            if session_identifier in SESSION_DIC:
                SESSION_DIC[session_identifier]['bytes'] = SESSION_DIC[session_identifier]['bytes'] + length
                SESSION_DIC[session_identifier]['end'] = tstamp
                SESSION_DIC[session_identifier]['cnt'] = SESSION_DIC[session_identifier]['cnt'] + 1
                if expert:
                    if expert in SESSION_DIC[session_identifier]['expert']:
                        SESSION_DIC[session_identifier]['expert'][expert] = SESSION_DIC[session_identifier]['expert'][expert] + 1
                    else:
                        SESSION_DIC[session_identifier]['expert'][expert] = 1
                if aggregate:
                    if src_port:
                        if src_port < SESSION_DIC[session_identifier]['src_port_lo']:
                            SESSION_DIC[session_identifier]['src_port_lo'] = src_port

                        if src_port > SESSION_DIC[session_identifier]['src_port_hi']:
                            SESSION_DIC[session_identifier]['src_port_hi'] = src_port
            else:
                SESSION_DIC[session_identifier] = {}
                SESSION_DIC[session_identifier]['cnt'] = 1
                SESSION_DIC[session_identifier]['vlan'] = vlan
                SESSION_DIC[session_identifier]['src'] = src
                SESSION_DIC[session_identifier]['dst'] = dst
                SESSION_DIC[session_identifier]['bytes'] = length
                SESSION_DIC[session_identifier]['start'] = tstamp
                SESSION_DIC[session_identifier]['expert'] = {}
                if expert:
                    SESSION_DIC[session_identifier]['expert'][expert] = 1
                if proto:
                    SESSION_DIC[session_identifier]['proto'] = proto
                if src_port:
                    if aggregate:
                        SESSION_DIC[session_identifier]['src_port_lo'] = src_port
                        SESSION_DIC[session_identifier]['src_port_hi'] = src_port
                    else:
                        SESSION_DIC[session_identifier]['src_port'] = src_port
                if dst_port:
                    SESSION_DIC[session_identifier]['dst_port'] = dst_port

        if expert and expert not in EXPERT_LIST:
            EXPERT_LIST.append(expert)

    def pkt_meta_data(self, pkt, p_expert):
        """ collect packet meta data from packet """
        tstamp = pkt.sniff_timestamp
        length = int(pkt.length)

        try:
            vlan = pkt.vlan.id
        except:
            vlan = None
        try:
            src = pkt.ip.src
        except:
            src = None
        try:
            dst = pkt.ip.dst
        except:
            dst = None
        try:
            proto = pkt.transport_layer
        except:
            proto = None

        try:
            src_port = int(pkt[pkt.transport_layer].srcport)
        except:
            src_port = None
        try:
            dst_port = int(pkt[pkt.transport_layer].dstport)
        except:
            dst_port = None

        if(src_port and dst_port):
            (src, dst, src_port, dst_port) = self.align_session(src, dst, src_port, dst_port)

        expert = None
        if(proto == 'TCP' and p_expert):
            try:
                expert = pkt.tcp._ws_expert_message
                if 'Duplicate ACK' in expert:
                    expert = 'Duplicate ACK'
            except:
                pass

        if(src and dst):
            return(tstamp, length, vlan, src, dst, proto, src_port, dst_port, expert)
        else:
            return(None, None, None, None, None, None, None, None, None)

if __name__ == "__main__":

    START_UTS = int(time.time())

    # get arguments
    CONFIG_DIC = arg_parse()

    DEBUG = None
    # print arguments if debug flag is set
    if 'debug' in CONFIG_DIC:
        DEBUG = CONFIG_DIC['debug']
        print('active options:')
        for c in CONFIG_DIC:
            print('  {0}:\t{1}'.format(c, CONFIG_DIC[c]))

    print_out(DEBUG, 'Start: {0}'.format(START_UTS))

    # fill some variables from config dictionary
    AGGREGATE = False
    if 'aggregate' in CONFIG_DIC:
        AGGREGATE = True
    EXPERT = False
    if 'expert' in CONFIG_DIC:
        EXPERT = True

    if 'csv_export' in CONFIG_DIC:
        CSV_EXPORT = True

    SESSION_DIC = {}
    EXPERT_LIST = []

    PC = PcapHelper()
    if 'file' in CONFIG_DIC:
        print_out(DEBUG, 'we got a single pcap file \'{0}\' so lets open it...'.format(CONFIG_DIC['file']))
        PC.read_pcap(CONFIG_DIC['file'], AGGREGATE, EXPERT)
    elif 'directory' in CONFIG_DIC:
        print_out(DEBUG, 'we got a directory \'{0}\' so lets read file by file...'.format(CONFIG_DIC['directory']))
        PC.read_dir(CONFIG_DIC['directory'], AGGREGATE, EXPERT)

    if SESSION_DIC:
        # sort sessions by start time
        print_out(DEBUG, 'sort {0} sessions by timestamp'.format(len(SESSION_DIC)))

        if 'sort_by' in CONFIG_DIC:
            SESSION_LIST = sort_dic(SESSION_DIC, CONFIG_DIC['sort_by'], False)
        else:
            SESSION_LIST = sort_dic(SESSION_DIC, ['start'], False)

        # create report
        OUTPUT_FILE = CONFIG_DIC['output_file']

        if CSV_EXPORT:
            # set name of output file
            if not OUTPUT_FILE.endswith('.txt'):
                OUTPUT_FILE = '{0}.txt'.format(CONFIG_DIC['output_file'])
            print_out(DEBUG, 'write csv file {0}'.format(OUTPUT_FILE))
            create_csv(START_UTS, SESSION_LIST, SESSION_DIC, OUTPUT_FILE, EXPERT_LIST, AGGREGATE)
        else:
            # set name of output file
            if not OUTPUT_FILE .endswith('.xlsx'):
                OUTPUT_FILE = '{0}.xlsx'.format(CONFIG_DIC['output_file'])
            print_out(DEBUG, 'write excel file {0}'.format(OUTPUT_FILE))
            create_xlsx(START_UTS, SESSION_LIST, SESSION_DIC, OUTPUT_FILE, EXPERT_LIST, AGGREGATE)
    else:
        print('no sessions found....')

    if DEBUG:
        END_UTS = int(time.time())
        print_out(DEBUG, 'End: {0} duration: {1} seconds'.format(START_UTS, END_UTS - START_UTS))
