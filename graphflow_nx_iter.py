#!/usr/bin/python
#
#  Copyright (c) 2016 Czech Technical University
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  I acknowledge that my thesis is subject to the rights and obligations stip-
#  ulated by the Act No. 121/2000 Coll., the Copyright Act, as amended. In
#  accordance with Article 46(6) of the Act, I hereby grant a nonexclusive au-
#  thorization (license) to utilize this thesis, including any and all computer pro-
#  grams incorporated therein or attached thereto and all corresponding docu-
#  mentation (hereinafter collectively referred to as the "Work"), to any and all
#  persons that wish to utilize the Work. Such persons are entitled to use the
#  Work in any way (including for-profit purposes) that does not detract from its
#  value. This authorization is not limited in terms of time, location and quan-
#  tity. However, all persons that makes use of the above license shall be obliged
#  to grant a license at least in the same scope as defined above with respect to
#  each and every work that is created (wholly or in part) based on the Work, by
#  modifying the Work, by combining the Work with another work, by including
#  the Work in a collection of works or by adapting the Work (including trans-
#  lation), and at the same time make available the source code of such work at
#  least in a way and scope that are comparable to the way and scope in which
#  the source code of the Work is made available.
#
#  $Author:Tomas Vicher
#
#  GraphFlow module for Nemea




import sys

import os.path

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "..", "python"))
sys.path.append("/home/tom/nemea/nemea-install/share/nemea-python/")
sys.path.append("/usr/local/lib/python2.7/dist-packages/")
import trap
import unirec
import networkx as nx
import time
import datetime
import ipaddress
import json
from networkx.readwrite import json_graph
import logging
from collections import deque
import hwt
import matplotlib.pyplot as plt


##Number of minutes in one period of time-serie (length of time window in minutes).
AGGREGATION_PERIOD_MINUTES = 5

##Number of periods in one hour.
HOUR_PERIODS_COUNT = 60 / AGGREGATION_PERIOD_MINUTES

##Number of periods in one day.
DAY_PERIODS_COUNT = 24 * HOUR_PERIODS_COUNT

##Number of periods in one week.
WEEK_AGGREGATION_PERIODS_COUNT = 7 * DAY_PERIODS_COUNT

##Number of periods in two weeks
TWO_WEEK_AGGREGATION_PERIODS_COUNT = 2 * WEEK_AGGREGATION_PERIODS_COUNT

##Number of periods with anomaly detected before report.
NUM_PERIODS_REPORT = 3

##Length of period for graph plotting in hours.
GRAPH_STRUCTURE_PLOT_INTERVAL_DAYS = 1

##Number of seconds in on period (length of time window in seconds).
TIME_WINDOW_SECONDS = 60 * AGGREGATION_PERIOD_MINUTES

##Size of batch of intervals to be prediceted in every new prediction event.
PREDICTION_INTERVALS = 1

##Decalaration of Holt-Winters deviation constatnt.
HWT_SCALING_FACTOR = 2.5

##Number of flows during one period dividing traffic to low/high usage.
THRESHOLD = 45000

##Minimal number of flows during one period to detect anomaly.
MINIMUM_FLOW_DETECTION_THRESHOLD = 100

##Number of periods for change state of traffic. (low/high)
TRAFFIC_STATE_CHANGE_PERIOD = 12

##Parameters accepted by module to be processed.
ALLOWED_PROPERTIES = ["PORT", "BYTES", "PACKETS", "DST_PORT", "SRC_PORT", "HTTP_RSP_CODE", "PROTOCOL", "TCP_FLAGS",
                      "TTL", "TIME_FIRST", "TIME_LAST"]

##Initialization of graph structure
gr = nx.DiGraph(flow_count=deque(), last_flow=0, prediction_count=PREDICTION_INTERVALS, detection_seq=0,
                prediction_sum=0,
                prediction_eval=0, values_last_sum=0, hwt_flow=deque(), hwt_flow_last=0,
                hwt_params=[None, None, None],
                hwt_a=deque(), hwt_s=deque(), hwt_s2=deque(), hwt_Y=deque(), hwt_deviation=deque(),
                flow_prediction_list=deque(),
                flow_prediction_list_total=deque(),
                measured_data_list=deque(), measured_data_list_total=deque(), deviation_list=deque(),
                deviation_list_total=deque())

logging.addLevelName(45, "ANOMALY")
logger = logging.getLogger(__name__)
setattr(logger, 'anomaly', lambda *args: logger.log(45, *args))

# Parses of module arguments
from optparse import OptionParser

parser = OptionParser(add_help_option=False)
parser.add_option("-l", "--learning",
                  action="store_true", dest="learning", default=False,
                  help="Turns learning phase on and off. Choose True/False")
parser.add_option("-p", "--properties",
                  dest="properties", default=None,
                  help="Set properties to be saved. Separated by comma. Its possible to choose from: " + str(
                      ALLOWED_PROPERTIES))
parser.add_option("-s", "--logger-severity",
                  dest="logger_severity", default="ANOMALY",
                  help="Set severity for logger from: info, debug, warning, error")
parser.add_option("-w", "--whitelist-path",
                  dest="whitelist_file_path", default="whitelist.txt",
                  help="List of known IP addresses. Default whitelist.txt.")
parser.add_option("-r", "--ip-range",
                  dest="ip_range", default=None,
                  help="Set range of ip addresses in local network first ip-last ip ")
parser.add_option("-g", "--plot-interval",
                  dest="plot_interval",
                  help="Set interval between plotting graphs in hours.")
parser.add_option("-f", "--file-path", dest="file_path",
                  help="Set path of file to save data or load data. Path is relative from current path. If parameter is not set, default value is data/learned.json",
                  default="data/learned.json")
parser.add_option("-q", "--quiet",
                  action="store_false", dest="verbose", default=True,
                  help="don't print status messages to stdout")


# ------------------------------------------------------




def FlowProcess(gr):
    next_period_counter = 0
    rec_buffer = []
    next_period = False
    UR_Flow = None
    plot_interval = 0
    logger_severity, prop_array, ip_range, file_path, is_learning, plot_interval_periods, whitelist_file_path = ParseAdditionalParams(
        parser)
    LoggerInitialization(logger_severity)
    quiet_period = True
    known_nodes_set = set()
    known_edges_set = set()
    prediction_initialized = False
    data_exported = True
    ## Read data from input interface
    rec, UR_Flow = DataLoader(UR_Flow)
    if not rec == -1:
        stats_trigger = rec.TIME_LAST.getSec() - (rec.TIME_LAST.getSec() % 60) + (10 * 60)
        if not is_learning:
            gr = ImportData(rec, file_path)
            print gr.graph['hwt_params']

            DataProcessInitialization(gr, known_nodes_set, known_edges_set, whitelist_file_path)
        ## Main loop (trap.stop is set to True when SIGINT or SIGTERM is received)
        while not trap.stop:
            if rec.TIME_LAST.getSec() > stats_trigger:
                next_period = True
                next_period_counter += 1
                print "period: ", next_period_counter
                #print "next period", len(gr.nodes()),"nodes, ",len(gr.edges()),"edges"
                if not is_learning:
                    if plot_interval_periods is not None:
                        plot_interval += 1
                    known_nodes_set = ImportWhitelist(whitelist_file_path,"node")
                    known_edges_set = ImportWhitelist(whitelist_file_path,"edge")
                    CleanGraph(gr)
                    FlowAnalysis(gr, NUM_PERIODS_REPORT)
                    NodeAnalysis(gr, NUM_PERIODS_REPORT, known_nodes_set)
                    EdgeAnalysis(gr, NUM_PERIODS_REPORT, known_edges_set)
                    quiet_period = QuietPeriodProcess(gr, THRESHOLD, TRAFFIC_STATE_CHANGE_PERIOD, quiet_period)
                    prediction_initialized = True


            if len(gr.graph['flow_count']) >= TWO_WEEK_AGGREGATION_PERIODS_COUNT and is_learning == True:
                is_learning = False
                data_exported = False
                known_nodes_set, known_edges_set = DataProcessInitialization(gr, known_nodes_set, known_edges_set,whitelist_file_path)

            if prediction_initialized and not data_exported:
                ExportData(file_path)
                data_exported = True

            # if not is_learning and plot_interval >= plot_interval_periods and plot_interval_periods is not None and TimestampToStr('%H', gr.graph['last_flow']) == "03" and TimestampToStr('%w', gr.graph['last_flow']) == "1":
            if not is_learning and plot_interval >= plot_interval_periods and plot_interval_periods is not None and TimestampToStr(
                    '%H', gr.graph['last_flow']) == "03":
                PlotData(gr, False)
                plot_interval = 0

            gr, is_learning, next_period, stats_trigger, rec_buffer,known_edges_set,known_nodes_set = FillGraph(gr, rec, ip_range, is_learning,
                                                                                prop_array, next_period,
                                                                                stats_trigger, rec_buffer, file_path,
                                                                                known_nodes_set, known_edges_set,whitelist_file_path)

            ## Read data from input interface
            rec, UR_Flow = DataLoader(UR_Flow)
            if rec == -1:
                break

        for record in rec_buffer:
            gr = AddRecord(record, gr, ip_range, next_period, is_learning)
            next_period = False
        if len(gr.graph['flow_count']) >= (TWO_WEEK_AGGREGATION_PERIODS_COUNT) and is_learning == True:
            ExportData(file_path)
        PlotData(gr, True)
    return gr


def CleanGraph(gr):
    for node, data in gr.nodes(data=True):
        if all(v == 0 for v in data['time']):
            print "removing ", node
            gr.remove_node(node)

    return gr


def DataProcessInitialization(gr, known_nodes_set, known_edges_set, whitelist_file_path):
    gr.graph['prediction_count'] = PREDICTION_INTERVALS
    for node_id in gr.nodes():
        gr.node[node_id]['prediction_count'] = PREDICTION_INTERVALS
        if gr.node[node_id]['permanent_addr']:
            known_nodes_set.add(node_id)
    for src, dst in gr.edges():
        gr[src][dst]['prediction_count'] = PREDICTION_INTERVALS
        if gr[src][dst]['permanent_edge']:
            known_edges_set.add((src, dst))
    ExportWhitelist(gr,known_nodes_set, whitelist_file_path, "node")
    ExportWhitelist(gr,known_edges_set, whitelist_file_path, "edge")
    return known_nodes_set, known_edges_set


def ImportWhitelist(whitelist_file_path,type):
    try:
        (filepath, filename) = os.path.split(whitelist_file_path)
        if type == "node":
            whitelist_file_path = filepath + "IP-" + filename
        elif type == "edge":
            whitelist_file_path = filepath + "Connection-" + filename
        else:
            print "Specify node / edge to read."
            return list()
        if not os.path.exists(whitelist_file_path):
            print "Could not find learned data, start with -l parameter first."
            return list()
        filehandle = open(str(whitelist_file_path), 'r')
    except:
        print "Could not find learned data, start with -l parameter first.."
        return list()

    processed_data = set()
    for line in filehandle:
        raw_data = line.strip().split(';')
        for tup in raw_data:
            if type == "edge":
                tup = tup.strip().strip('(').strip(')').split(',')
                if len(tup) == 2:
                    res = tuple(((unicode(tup[0])),(unicode(tup[1]))))
                    processed_data.add(res)
            else:
                processed_data.add(unicode(tup))
    return processed_data

def ExportWhitelist(gr,whitelist, whitelist_file_path, type):
    whitelist_file_path_all = ""
    try:
        (filepath, filename) = os.path.split(whitelist_file_path)
        if type == "node":
            whitelist_file_path = filepath + "IP-" + filename
            whitelist_file_path_all = filepath + "IP-ALL-" + filename
        elif type == "edge":
            whitelist_file_path = filepath + "Connection-" + filename
            whitelist_file_path_all = filepath + "Connection-ALL-" + filename
        else:
            print "Specify node / edge to read."
            return
        print filepath, filename
        if filepath:
            if not os.path.exists(filepath):
                os.makedirs(filepath)
        filehandle = open(str(whitelist_file_path), 'w')
        filehandle_all = open(str(whitelist_file_path_all), 'w')
    except IOError:
        print "Can not write data."
        return
    print gr.edges()
    if type == "edge":
        for item in whitelist:
            filehandle.write("(" + unicode(item[0]) + "," + unicode(item[1]) + ")" + ';')
        for item in gr.edges():
            filehandle_all.write("(" + unicode(item[0]) + "," + unicode(item[1]) + ")" + ';')
    else:
        for item in whitelist:
            filehandle.write(unicode(item) + ';')
        for item in gr.nodes():
            filehandle_all.write(unicode(item) + ';')




def PlotData(gr, is_total):
    if is_total:
        prediction = "flow_prediction_list_total"
        measured = "measured_data_list_total"
        deviation = "deviation_list_total"

    else:
        prediction = "flow_prediction_list"
        measured = "measured_data_list"
        deviation = "deviation_list"

    for src, dst in gr.edges():
        if gr.edge[src][dst]['permanent_edge']:
            print src, dst
            img_path = "img/flow-" + src + "-" + dst + "/" + TimestampToStr('%Y-%m-%d %H:%M', gr.graph['last_flow'])
            PlotFlow(gr[src][dst][prediction], gr[src][dst][measured], gr[src][dst][deviation], img_path,
                     gr.graph['last_flow'])
            gr.edge[src][dst][prediction] = deque()
            gr.edge[src][dst][measured] = deque()
            gr.edge[src][dst][deviation] = deque()

    for ipaddr in gr.nodes():
        if gr.node[ipaddr]['permanent_addr']:
            print ipaddr
            img_path = "img/ip-" + ipaddr + "/" + TimestampToStr('%Y-%m-%d %H:%M', gr.graph['last_flow'])
            PlotFlow(gr.node[ipaddr][prediction], gr.node[ipaddr][measured], gr.node[ipaddr][deviation], img_path,
                     gr.graph['last_flow'])
            gr.node[ipaddr][prediction] = deque()
            gr.node[ipaddr][measured] = deque()
            gr.node[ipaddr][deviation] = deque()

    img_path = "img/total/" + TimestampToStr('%Y-%m-%d %H:%M', gr.graph['last_flow'])
    PlotFlow(gr.graph[prediction], gr.graph[measured], gr.graph[deviation], img_path, gr.graph['last_flow'])
    PlotGraph(gr, img_path)
    gr.graph['flow_prediction_list'] = deque()
    gr.graph['measured_data_list'] = deque()
    gr.graph['deviation_list'] = deque()


def PlotGraph(gr, img_path):
    node_plot_list = []
    edge_plot_list = []
    plt.figure()
    gr_to_export = nx.DiGraph()

    try:
        (filepath, filename) = os.path.split(img_path)
        if not os.path.exists(filepath):
            os.makedirs(filepath)
        for node, data in gr.nodes(data=True):
            for count in list(data['time'])[-GRAPH_STRUCTURE_PLOT_INTERVAL_DAYS * DAY_PERIODS_COUNT:]:
                if count > 0:
                    node_plot_list.append(node)
                    gr_to_export.add_node(node)
                    break
        for src, dst, data in gr.edges(data=True):
            for count in list(data['time'])[-GRAPH_STRUCTURE_PLOT_INTERVAL_DAYS * DAY_PERIODS_COUNT:]:
                if count > 0:
                    edge_plot_list.append([src, dst])
                    gr_to_export.add_edge(src, dst)
                    break
        nx.draw_shell(gr, nodelist=node_plot_list, edgelist=edge_plot_list, font_color="c", arrows=True,
                      with_labels=True)
        print str(img_path) + 'graph.pdf'
        nx.write_gexf(gr_to_export, str(img_path) + 'graph.gexf')
        plt.savefig(str(img_path) + 'graph.pdf')
    except IOError:
        print "Can not write image data."
        return
    plt.cla()
    plt.clf()
    plt.close()


def PlotFlow(flow_prediction_list, measured_data_list, deviation_list, img_path, last_flow):
    plt.figure(None, (7, 5))
    plt.rc('font', family='serif', size=14)
    plt.rc('legend', fontsize=14)
    # print flow_prediction_list, measured_data_list
    time_list = [datetime.datetime.fromtimestamp(
        last_flow - len(flow_prediction_list) * TIME_WINDOW_SECONDS) + datetime.timedelta(
        minutes=i * AGGREGATION_PERIOD_MINUTES) for i in range(len(flow_prediction_list))]
    # print len(time_list), len(measured_data_list)
    # print time_list
    interval_low = []
    interval_high = []
    for dev, predicted_value in zip(deviation_list, flow_prediction_list):
        interval_low.append(predicted_value - dev)
        interval_high.append(predicted_value + dev)

    try:
        (filepath, filename) = os.path.split(img_path)
        if not os.path.exists(filepath):
            os.makedirs(filepath)
        plt.plot(time_list, measured_data_list, label='measured data')
        plt.legend(loc='upper center', bbox_to_anchor=(0.5, 1.15),
                   fancybox=True, shadow=True, ncol=5)
        plt.gcf().autofmt_xdate()
        plt.ylabel('Numer of flows per 5 minutes')
        plt.savefig(str(img_path) + 'weekdemostration' + '.png')
        # plt.show()
        if len(deviation_list) > 0:
            plt.plot(time_list, interval_low, label='lower limit')
            plt.plot(time_list, interval_high, label='upper limit')
        else:
            plt.plot(time_list, flow_prediction_list, label='real data')
        plt.legend(loc='upper center', bbox_to_anchor=(0.5, 1.15),
                   fancybox=True, shadow=True, ncol=5)

        plt.savefig(str(img_path) + '.png')

    except IOError:
        print "Can not write image data."
        return
    plt.cla()
    plt.clf()
    plt.close()
    print "plotting"


def DataLoader(UR_Flow):
    try:
        data = trap.recv(0)
    except trap.EFMTMismatch:
        print("Error: output and input interfaces data format or data specifier mismatch")
        return -1, -1
    except trap.EFMTChanged as e:
        # Get data format from negotiation
        (fmttype, fmtspec) = trap.get_data_fmt(trap.IFC_INPUT, 0)
        UR_Flow = unirec.CreateTemplate("UR_Flow", fmtspec)
        data = e.data
    except trap.ETerminated:
        print "fmt exception"
        return -1, -1

    # Check for "end-of-stream" record
    if len(data) <= 1:
        return -1, -1

    return UR_Flow(data), UR_Flow


def LoggerInitialization(logger_severity):
    handler = logging.FileHandler('graphflow.log' + str(datetime.datetime.now()))
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    level = logging.getLevelName(logger_severity)
    logging.getLogger().setLevel(level)


def EdgeAnalysis(gr, num_blocks_report, known_edges_set):
    for src, dst in gr.edges():
        if gr[src][dst]['time'][-1] == 0:
            if gr[src][dst]['time'][-2] != 0:
                if (src, dst) in known_edges_set:
                    logger.info('Known connection: (%s,%s) disconnected in time: %s', src, dst,
                                TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))
                else:
                    logger.anomaly('Unknown connection: (%s,%s) disconnected in time: %s', src, dst,
                                   TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))

        elif gr[src][dst]['time'][-2] == 0:
            if (src, dst) in known_edges_set:
                logger.info('Known connection (%s,%s) connected in time: %s', src, dst,
                            TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))
            else:
                logger.anomaly('Unknown connection (%s,%s) connected in time: %s', src, dst,
                               TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))

        if not 0 in gr[src][dst]['time'] and not gr[src][dst]['permanent_edge']:
            gr[src][dst]['permanent_edge'] = True
            gr[src][dst]['prediction_count'] = PREDICTION_INTERVALS
            gr[src][dst]['hwt_edge'] = deque()
            logger.info('New regular connection: (%s,%s) in last 2 weeks before: %s', src, dst,
                        TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))
        if 0 in gr[src][dst]['time'] and gr[src][dst]['permanent_edge']:
            gr[src][dst]['permanent_edge'] = False
            logger.info('Regular connection: (%s,%s) disconected in last 2 weeks before: %s', src, dst,
                        TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))

        if len(gr[src][dst]['time']) >= (TWO_WEEK_AGGREGATION_PERIODS_COUNT):
            if len(gr[src][dst]['hwt_edge']) > 0 and gr[src][dst]['permanent_edge']:

                if len(gr[src][dst]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                    hwt_flow_deviation = abs(gr[src][dst]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                    gr[src][dst]['deviation_list'].append(
                        gr[src][dst]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                    gr[src][dst]['deviation_list_total'].append(
                        gr[src][dst]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                else:
                    hwt_flow_deviation = abs(gr[src][dst]['hwt_deviation'][-1])
                    gr[src][dst]['deviation_list'].append(gr[src][dst]['hwt_deviation'][-1])
                    gr[src][dst]['deviation_list_total'].append(gr[src][dst]['hwt_deviation'][-1])
                current_prediction_count = gr[src][dst]['prediction_count']
                gr[src][dst]['flow_prediction_list'].append(gr[src][dst]['hwt_edge'][current_prediction_count])
                gr[src][dst]['measured_data_list'].append(gr[src][dst]['time'][-1])
                gr[src][dst]['flow_prediction_list_total'].append(gr[src][dst]['hwt_edge'][current_prediction_count])
                gr[src][dst]['measured_data_list_total'].append(gr[src][dst]['time'][-1])
                if abs(gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][
                    current_prediction_count]) > hwt_flow_deviation * HWT_SCALING_FACTOR:
                    # print "used edge deviation",hwt_flow_deviation
                    gr[src][dst]['detection_seq'] += 1
                    gr[src][dst]['prediction_sum'] += gr[src][dst]['hwt_edge'][current_prediction_count]
                    gr[src][dst]['values_last_sum'] += int(gr[src][dst]['time'][-1])
                    if gr[src][dst]['detection_seq'] == num_blocks_report:
                        if int(gr[src][dst]['values_last_sum'] / num_blocks_report) > MINIMUM_FLOW_DETECTION_THRESHOLD:
                            logger.anomaly(
                                'Connection (%s,%s) flows count: %s prediction: %s per %s miutes during last %s minutes before %s',
                                src, dst,
                                int(gr[src][dst]['values_last_sum'] / num_blocks_report),
                                int(gr[src][dst]['prediction_sum'] / num_blocks_report),
                                AGGREGATION_PERIOD_MINUTES,
                                num_blocks_report * AGGREGATION_PERIOD_MINUTES,
                                TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))
                        gr[src][dst]['detection_seq'] = 0
                        gr[src][dst]['prediction_sum'] = 0
                        gr[src][dst]['values_last_sum'] = 0

                    # gr[src][dst]['time'][-1] = gr[src][dst]['hwt_edge'][current_prediction_count]

                    gr[src][dst]['hwt_a'].pop()
                    gr[src][dst]['hwt_s'].pop()
                    gr[src][dst]['hwt_s2'].pop()
                    gr[src][dst]['hwt_edge'][-1], gr[src][dst]['hwt_a'], gr[src][dst]['hwt_s'], gr[src][dst][
                        'hwt_s2'] = hwt.HWTStep(gr[src][dst]['hwt_edge_last'], gr[src][dst]['hwt_a'],
                                                gr[src][dst]['hwt_s'], gr[src][dst]['hwt_s2'],
                                                gr[src][dst]['hwt_params'][0], gr[src][dst]['hwt_params'][1],
                                                gr[src][dst]['hwt_params'][2], DAY_PERIODS_COUNT,
                                                WEEK_AGGREGATION_PERIODS_COUNT, )
                    if len(gr[src][dst]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                        gr[src][dst]['hwt_deviation'][-1] = gr[src][dst]['hwt_deviation'][
                            -WEEK_AGGREGATION_PERIODS_COUNT]
                    elif len(gr[src][dst]['hwt_deviation']) > 1:
                        gr[src][dst]['hwt_deviation'][-1] = gr[src][dst]['hwt_deviation'][-2]
                else:
                    gr[src][dst]['detection_seq'] = 0
                    gr[src][dst]['prediction_sum'] = 0
                    gr[src][dst]['values_last_sum'] = 0
            gr[src][dst]['prediction_count'] += 1

            if gr[src][dst]['prediction_count'] >= PREDICTION_INTERVALS:
                if len(gr[src][dst]['hwt_edge']) > 0:
                    gr[src][dst]['hwt_edge_last'] = gr[src][dst]['hwt_edge'][-1]
                gr[src][dst]['prediction_count'] = 0
                if gr[src][dst]['permanent_edge']:

                    if gr[src][dst]['hwt_params'][0] is None or gr[src][dst]['hwt_params'][1] is None or \
                                    gr[src][dst]['hwt_params'][2] is None:
                        gr[src][dst]['hwt_edge'], gr[src][dst]['hwt_params'], _, gr[src][dst]['hwt_a'], gr[src][dst][
                            'hwt_s'], gr[src][dst]['hwt_s2'], gr[src][dst]['hwt_Y'] = hwt.HWT(
                            list(gr[src][dst]['time']), DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT,
                            PREDICTION_INTERVALS,
                            alpha=gr[src][dst]['hwt_params'][0], gamma=gr[src][dst]['hwt_params'][1],
                            delta=gr[src][dst]['hwt_params'][2],
                            initial_values_optimization=[0.1, 0.2, 0.2])
                        gr[src][dst]['hwt_edge_last'] = gr[src][dst]['hwt_edge'][-1]
                        gr[src][dst]['hwt_deviation'].append(
                            abs(gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][-1]))



                    else:
                        if len(gr[src][dst]['hwt_edge']) > 0:
                            if len(gr[src][dst]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                                gr[src][dst]['hwt_deviation'].append(abs((gr[src][dst]['hwt_params'][1] * (
                                    gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][-1])) + (
                                                                             (1 - gr[src][dst]['hwt_params'][1]) *
                                                                             gr[src][dst]['hwt_deviation'][
                                                                                 -WEEK_AGGREGATION_PERIODS_COUNT])))
                            else:
                                gr[src][dst]['hwt_deviation'].append(
                                    abs((gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][-1])))
                        if len(gr[src][dst]['hwt_edge']) == 0:
                            gr[src][dst]['hwt_edge'].append(0)
                        gr[src][dst]['hwt_edge'][-1], gr[src][dst]['hwt_a'], gr[src][dst]['hwt_s'], gr[src][dst][
                            'hwt_s2'] = hwt.HWTStep(gr[src][dst]['time'][-1], gr[src][dst]['hwt_a'],
                                                    gr[src][dst]['hwt_s'], gr[src][dst]['hwt_s2'],
                                                    gr[src][dst]['hwt_params'][0], gr[src][dst]['hwt_params'][1],
                                                    gr[src][dst]['hwt_params'][2], DAY_PERIODS_COUNT,
                                                    WEEK_AGGREGATION_PERIODS_COUNT, )


def NodeAnalysis(gr, num_blocks_report, known_nodes_set):
    for node_id in gr.nodes():
        if gr.node[node_id]['time'][-1] == 0:
            if gr.node[node_id]['time'][-2] != 0:
                if node_id in known_nodes_set:
                    logger.info('Known IP address: %s disconnected in time: %s', node_id,
                                TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))
                else:
                    logger.anomaly('Unknown IP address: %s disconnected in time: %s', node_id,
                                   TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))
        elif gr.node[node_id]['time'][-2] == 0:
            if node_id in known_nodes_set:
                logger.info('Known IP address: %s connected in time: %s', node_id,
                            TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))
            else:
                logger.anomaly('Unknown IP address: %s connected in time: %s', node_id,
                               TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))

        if not 0 in gr.node[node_id]['time'] and not gr.node[node_id]['permanent_addr']:
            gr.node[node_id]['permanent_addr'] = True
            gr.node[node_id]['prediction_count'] = PREDICTION_INTERVALS
            gr.node[node_id]['hwt_addr'] = deque()
            logger.info('New regular IP address: %s in last 2 weeks before:%s', node_id,
                        TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))
        if 0 in gr.node[node_id]['time'] and gr.node[node_id]['permanent_addr']:
            gr.node[node_id]['permanent_addr'] = False
            logger.info('Regular IP address: %s disconnected in last 2 weeks before:%s', node_id,
                        TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))

        if len(gr.node[node_id]['time']) >= TWO_WEEK_AGGREGATION_PERIODS_COUNT:
            if len(gr.node[node_id]['hwt_addr']) > 0 and gr.node[node_id]['permanent_addr'] == True:
                if len(gr.node[node_id]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                    hwt_flow_deviation = abs(gr.node[node_id]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                    gr.node[node_id]['deviation_list'].append(
                        gr.node[node_id]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                    gr.node[node_id]['deviation_list_total'].append(
                        gr.node[node_id]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                else:
                    hwt_flow_deviation = abs(gr.node[node_id]['hwt_deviation'][-1])
                    gr.node[node_id]['deviation_list'].append(gr.node[node_id]['hwt_deviation'][-1])
                    gr.node[node_id]['deviation_list_total'].append(gr.node[node_id]['hwt_deviation'][-1])
                current_prediction_count = gr.node[node_id]['prediction_count']
                gr.node[node_id]['flow_prediction_list'].append(gr.node[node_id]['hwt_addr'][current_prediction_count])
                gr.node[node_id]['measured_data_list'].append(gr.node[node_id]['time'][-1])
                gr.node[node_id]['flow_prediction_list_total'].append(
                    gr.node[node_id]['hwt_addr'][current_prediction_count])
                gr.node[node_id]['measured_data_list_total'].append(gr.node[node_id]['time'][-1])
                if abs(gr.node[node_id]['time'][-1] - gr.node[node_id]['hwt_addr'][
                    current_prediction_count]) > hwt_flow_deviation * HWT_SCALING_FACTOR:
                    # print "used node deviation",hwt_flow_deviation
                    gr.node[node_id]['detection_seq'] += 1
                    gr.node[node_id]['prediction_sum'] += gr.node[node_id]['hwt_addr'][current_prediction_count]
                    gr.node[node_id]['values_last_sum'] += int(gr.node[node_id]['time'][-1])
                    if gr.node[node_id]['detection_seq'] == num_blocks_report:
                        if int(gr.node[node_id][
                                   'values_last_sum'] / num_blocks_report) > MINIMUM_FLOW_DETECTION_THRESHOLD:
                            logger.anomaly(
                                'IP %s flows count:%s prediction:%s per %s miutes during last %s minutes before %s',
                                node_id,
                                int(gr.node[node_id]['values_last_sum'] / num_blocks_report),
                                int(gr.node[node_id]['prediction_sum'] / num_blocks_report),
                                AGGREGATION_PERIOD_MINUTES,
                                num_blocks_report * AGGREGATION_PERIOD_MINUTES,
                                TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))
                        gr.node[node_id]['detection_seq'] = 0
                        gr.node[node_id]['prediction_sum'] = 0
                        gr.node[node_id]['values_last_sum'] = 0
                    # gr.node[node_id]['time'][-1] = gr.node[node_id]['hwt_addr'][current_prediction_count]
                    gr.node[node_id]['hwt_a'].pop()
                    gr.node[node_id]['hwt_s'].pop()
                    gr.node[node_id]['hwt_s2'].pop()

                    gr.node[node_id]['hwt_addr'][-1], gr.node[node_id]['hwt_a'], gr.node[node_id]['hwt_s'], \
                    gr.node[node_id][
                        'hwt_s2'] = hwt.HWTStep(gr.node[node_id]['hwt_addr_last'], gr.node[node_id]['hwt_a'],
                                                gr.node[node_id]['hwt_s'], gr.node[node_id]['hwt_s2'],
                                                gr.node[node_id]['hwt_params'][0], gr.node[node_id]['hwt_params'][1],
                                                gr.node[node_id]['hwt_params'][2], DAY_PERIODS_COUNT,
                                                WEEK_AGGREGATION_PERIODS_COUNT, )
                    if len(gr.node[node_id]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                        gr.node[node_id]['hwt_deviation'][-1] = gr.node[node_id]['hwt_deviation'][
                            -WEEK_AGGREGATION_PERIODS_COUNT]
                    elif len(gr.node[node_id]['hwt_deviation']) > 1:
                        gr.node[node_id]['hwt_deviation'][-1] = gr.node[node_id]['hwt_deviation'][-2]

                else:
                    gr.node[node_id]['detection_seq'] = 0
                    gr.node[node_id]['prediction_sum'] = 0
                    gr.node[node_id]['values_last_sum'] = 0
                gr.node[node_id]['prediction_count'] += 1

            if gr.node[node_id]['prediction_count'] >= PREDICTION_INTERVALS:
                if len(gr.node[node_id]['hwt_addr']) > 0:
                    gr.node[node_id]['hwt_addr_last'] = gr.node[node_id]['hwt_addr'][-1]
                gr.node[node_id]['prediction_count'] = 0
                if gr.node[node_id]['permanent_addr'] == True:
                    if gr.node[node_id]['hwt_params'][0] is None or gr.node[node_id]['hwt_params'][1] is None or \
                                    gr.node[node_id]['hwt_params'][2] is None:
                        gr.node[node_id]['hwt_addr'], gr.node[node_id]['hwt_params'], _, gr.node[node_id]['hwt_a'], \
                        gr.node[node_id]['hwt_s'], gr.node[node_id]['hwt_s2'], gr.node[node_id]['hwt_Y'] = hwt.HWT(
                            list(gr.node[node_id]['time']), DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT,
                            PREDICTION_INTERVALS,
                            alpha=gr.node[node_id]['hwt_params'][0], gamma=gr.node[node_id]['hwt_params'][1],
                            delta=gr.node[node_id]['hwt_params'][2],
                            initial_values_optimization=[0.1, 0.2, 0.2])
                        gr.node[node_id]['hwt_addr_last'] = gr.node[node_id]['hwt_addr'][-1]
                        gr.node[node_id]['hwt_deviation'].append(
                            abs(gr.node[node_id]['time'][-1] - gr.node[node_id]['hwt_addr'][-1]))



                    else:

                        if len(gr.node[node_id]['hwt_addr']) > 0:
                            if len(gr.node[node_id]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                                gr.node[node_id]['hwt_deviation'].append(abs((gr.node[node_id]['hwt_params'][1] * (
                                    gr.node[node_id]['time'][-1] - gr.node[node_id]['hwt_addr'][-1])) + (
                                                                                 (1 - gr.node[node_id]['hwt_params'][
                                                                                     1]) *
                                                                                 gr.node[node_id]['hwt_deviation'][
                                                                                     -WEEK_AGGREGATION_PERIODS_COUNT])))
                            else:
                                gr.node[node_id]['hwt_deviation'].append(
                                    abs((gr.node[node_id]['time'][-1] - gr.node[node_id]['hwt_addr'][-1])))
                        if len(gr.node[node_id]['hwt_addr']) == 0:
                            gr.node[node_id]['hwt_addr'].append(0)
                        gr.node[node_id]['hwt_addr'][-1], gr.node[node_id]['hwt_a'], gr.node[node_id]['hwt_s'], \
                        gr.node[node_id]['hwt_s2'] = hwt.HWTStep(gr.node[node_id]['time'][-1],
                                                                 gr.node[node_id]['hwt_a'], gr.node[node_id]['hwt_s'],
                                                                 gr.node[node_id]['hwt_s2'],
                                                                 gr.node[node_id]['hwt_params'][0],
                                                                 gr.node[node_id]['hwt_params'][1],
                                                                 gr.node[node_id]['hwt_params'][2], DAY_PERIODS_COUNT,
                                                                 WEEK_AGGREGATION_PERIODS_COUNT, )


def FlowAnalysis(gr, num_blocks_report):
    if len(gr.graph['flow_count']) >= TWO_WEEK_AGGREGATION_PERIODS_COUNT:
        if len(gr.graph['hwt_flow']) > 0:
            current_prediction_count = gr.graph['prediction_count']
            if len(gr.graph['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                hwt_flow_deviation = abs(gr.graph['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                gr.graph['deviation_list'].append(gr.graph['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                gr.graph['deviation_list_total'].append(gr.graph['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])

            else:
                hwt_flow_deviation = abs(gr.graph['hwt_deviation'][-1])
                gr.graph['deviation_list'].append(gr.graph['hwt_deviation'][-1])
                gr.graph['deviation_list_total'].append(gr.graph['hwt_deviation'][-1])


            gr.graph['flow_prediction_list'].append(gr.graph['hwt_flow'][current_prediction_count])
            gr.graph['measured_data_list'].append(gr.graph['flow_count'][-1])
            gr.graph['flow_prediction_list_total'].append(gr.graph['hwt_flow'][current_prediction_count])
            gr.graph['measured_data_list_total'].append(gr.graph['flow_count'][-1])

            if abs(gr.graph['flow_count'][-1] - gr.graph['hwt_flow'][
                current_prediction_count]) > hwt_flow_deviation * HWT_SCALING_FACTOR:
                # print "used flow deviation",hwt_flow_deviation
                gr.graph['detection_seq'] += 1
                gr.graph['prediction_sum'] += gr.graph['hwt_flow'][current_prediction_count]
                gr.graph['values_last_sum'] += int(gr.graph['flow_count'][-1])
                if gr.graph['detection_seq'] == num_blocks_report:
                    if int(gr.graph['values_last_sum'] / num_blocks_report) > MINIMUM_FLOW_DETECTION_THRESHOLD:
                        logger.anomaly(
                            'Average flow count: %s, average prediction count: %s per %s miutes during last %s minutes before %s',
                            int(gr.graph['values_last_sum'] / num_blocks_report),
                            int(gr.graph['prediction_sum'] / num_blocks_report),
                            AGGREGATION_PERIOD_MINUTES,
                            num_blocks_report * AGGREGATION_PERIOD_MINUTES,
                            TimestampToStr('%Y-%m-%d %H:%M', gr.graph['last_flow']))
                    gr.graph['detection_seq'] = 0
                    gr.graph['prediction_sum'] = 0
                    gr.graph['values_last_sum'] = 0
                gr.graph['hwt_a'].pop()
                gr.graph['hwt_s'].pop()
                gr.graph['hwt_s2'].pop()

                # print len(gr.graph['hwt_flow']),len(gr.graph['hwt_a']),len(gr.graph['hwt_flow_last'])
                gr.graph['hwt_flow'][-1], gr.graph['hwt_a'], gr.graph['hwt_s'], gr.graph['hwt_s2'] = hwt.HWTStep(
                    gr.graph['hwt_flow_last'], gr.graph['hwt_a'], gr.graph['hwt_s'], gr.graph['hwt_s2'],
                    gr.graph['hwt_params'][0], gr.graph['hwt_params'][1], gr.graph['hwt_params'][2], DAY_PERIODS_COUNT,
                    WEEK_AGGREGATION_PERIODS_COUNT, )
                if len(gr.graph['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                    gr.graph['hwt_deviation'][-1] = gr.graph['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT]
                elif len(gr.graph['hwt_deviation']) > 1:
                    gr.graph['hwt_deviation'][-1] = gr.graph['hwt_deviation'][-2]
            else:
                gr.graph['detection_seq'] = 0
                gr.graph['prediction_sum'] = 0
                gr.graph['values_last_sum'] = 0
            gr.graph['prediction_count'] += 1

        if gr.graph['prediction_count'] >= PREDICTION_INTERVALS:
            if len(gr.graph['hwt_flow']) > 0:
                gr.graph['hwt_flow_last'] = gr.graph['hwt_flow'][-1]
            gr.graph['prediction_count'] = 0
            if 0 not in gr.graph['flow_count']:
                if gr.graph['hwt_params'][0] is None or gr.graph['hwt_params'][1] is None or gr.graph['hwt_params'][
                    2] is None:
                    print "predpocitani"
                    gr.graph['hwt_flow'], gr.graph['hwt_params'], _, gr.graph['hwt_a'], gr.graph['hwt_s'], gr.graph[
                        'hwt_s2'], gr.graph['hwt_Y'] = hwt.HWT(list(gr.graph['flow_count']), DAY_PERIODS_COUNT,
                                                               WEEK_AGGREGATION_PERIODS_COUNT, PREDICTION_INTERVALS,
                                                               alpha=gr.graph['hwt_params'][0],
                                                               gamma=gr.graph['hwt_params'][1],
                                                               delta=gr.graph['hwt_params'][2],
                                                               initial_values_optimization=[0.5, 0.5, 0.5])

                    gr.graph['hwt_flow_last'] = gr.graph['hwt_flow'][-1]
                    gr.graph['hwt_deviation'].append(abs(gr.graph['flow_count'][-1] - gr.graph['hwt_flow'][-1]))


                else:
                    if len(gr.graph['hwt_flow']) > 0:
                        if len(gr.graph['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                            gr.graph['hwt_deviation'].append(abs((gr.graph['hwt_params'][1] * (
                                gr.graph['flow_count'][-1] - gr.graph['hwt_flow'][-1])) + (
                                                                 (1 - gr.graph['hwt_params'][1]) *
                                                                 gr.graph['hwt_deviation'][
                                                                     -WEEK_AGGREGATION_PERIODS_COUNT])))
                        else:
                            gr.graph['hwt_deviation'].append(abs(gr.graph['flow_count'][-1] - gr.graph['hwt_flow'][-1]))
                    if len(gr.graph['hwt_flow']) == 0:
                        gr.graph['hwt_flow'].append(0)
                    gr.graph['hwt_flow'][-1], gr.graph['hwt_a'], gr.graph['hwt_s'], gr.graph['hwt_s2'] = hwt.HWTStep(
                        gr.graph['flow_count'][-1], gr.graph['hwt_a'], gr.graph['hwt_s'], gr.graph['hwt_s2'],
                        gr.graph['hwt_params'][0], gr.graph['hwt_params'][1], gr.graph['hwt_params'][2],
                        DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT, )


def QuietPeriodProcess(gr, threshold, change_period, quiet_period):
    all_quiet = True
    all_peak = True
    for count in list(gr.graph['flow_count'])[-change_period:-2]:
        if count < threshold:
            all_peak = False
        else:
            all_quiet = False

    if all_peak and gr.graph['flow_count'][-1] < threshold and not quiet_period:
        logger.anomaly('Low traffic period started with %s flows per five minutes in time %s',
                       gr.graph['flow_count'][-1], TimestampToStr('%Y-%m-%d %H:%M', gr.graph['last_flow']))
        quiet_period = True
    elif all_quiet and gr.graph['flow_count'][-1] > threshold and quiet_period:
        logger.anomaly('High traffic period started with %s flows per five minutes in time %s',
                       gr.graph['flow_count'][-1], TimestampToStr('%Y-%m-%d %H:%M', gr.graph['last_flow']))
        quiet_period = False
    return quiet_period


def StrToDatetime(time_str, time_format):
    return datetime.datetime.strptime(time_str, time_format)


def TimestampToStr(time_format, timestamp):
    return time.strftime(time_format, time.gmtime(timestamp))


def CheckIPRange(ip, ip_range):
    if ip_range is not None:
        if not any(ipaddress.ip_address(unicode(ip, "utf-8")) in p for p in ip_range):
            ip = "0.0.0.0"

    return ip


def FillGraph(gr, rec, ip_range, is_learning, prop_array, next_period, stats_trigger, rec_buffer, file_path,
              known_nodes_set, known_edges_set,whitelist_file_path):
    if next_period:
        stats_trigger += TIME_WINDOW_SECONDS
        for record in rec_buffer:
            gr = AddRecord(record, gr, ip_range, next_period, is_learning)
            next_period = False
        rec_buffer = list()
        rec_buffer.append(rec)
    elif rec.TIME_LAST.getSec() > stats_trigger - TIME_WINDOW_SECONDS:
        rec_buffer.append(rec)
    elif rec.TIME_LAST.getSec() <= stats_trigger - TIME_WINDOW_SECONDS:
        gr = AddRecord(rec, gr, ip_range, next_period, is_learning)
        next_period = False
    return gr, is_learning, next_period, stats_trigger, rec_buffer,known_edges_set,known_nodes_set


def FillGraphRecord(gr, rec, next_period):
    if next_period or len(gr.graph['flow_count']) == 0:
        gr.graph['flow_count'].append(1)
    else:
        gr.graph['flow_count'][-1] += 1
    gr.graph['last_flow'] = rec.TIME_LAST.getSec()

    return gr


def FillEdgeRecord(src_ip, dst_ip, rec, gr):
    if gr.has_edge(src_ip, dst_ip):
        gr[src_ip][dst_ip]['last_seen'] = rec.TIME_LAST.getSec()
        gr[src_ip][dst_ip]['time'][-1] += 1
    else:
        gr.add_edge(src_ip, dst_ip, permanent_edge=False, detection_seq=0,
                    prediction_count=PREDICTION_INTERVALS, hwt_edge=deque(), hwt_edge_last=0,
                    hwt_params=[None, None, None], values_last_sum=0, prediction_sum=0,
                    prediction_eval=0, last_seen=rec.TIME_LAST.getSec(), time=deque(), hwt_a=deque(), hwt_s=deque(),
                    hwt_s2=deque(), hwt_Y=deque(), hwt_deviation=deque(), flow_prediction_list=deque(),
                    flow_prediction_list_total=deque(), measured_data_list=deque(), measured_data_list_total=deque(),
                    deviation_list=deque(), deviation_list_total=deque())
        while len(gr[src_ip][dst_ip]['time']) < len(gr.graph['flow_count']) - 1:
            gr[src_ip][dst_ip]['time'].append(0)
        gr[src_ip][dst_ip]['time'].append(1)
    return gr


def FillNodeRecord(ip, rec, gr):
    if gr.has_node(ip):
        gr.node[ip]['last_seen'] = rec.TIME_LAST.getSec()
        gr.node[ip]['time'][-1] += 1
    else:
        gr.add_node(ip, permanent_addr=False, detection_seq=0, prediction_count=PREDICTION_INTERVALS,
                    hwt_addr=deque(), hwt_addr_last=0, hwt_params=[None, None, None], values_last_sum=0,
                    prediction_sum=0, prediction_eval=0,
                    last_seen=rec.TIME_LAST.getSec(), time=deque(), hwt_a=deque(), hwt_s=deque(), hwt_s2=deque(),
                    hwt_Y=deque(), hwt_deviation=deque(), flow_prediction_list=deque(),
                    flow_prediction_list_total=deque(), measured_data_list=deque(), measured_data_list_total=deque(),
                    deviation_list=deque(), deviation_list_total=deque())
        while len(gr.node[ip]['time']) < len(gr.graph['flow_count']) - 1:
            gr.node[ip]['time'].append(0)
        gr.node[ip]['time'].append(1)

    return gr


def NextPeriodProcess(gr, next_period):
    if next_period:
        for parameter in ['flow_count', 'hwt_flow', 'hwt_a', 'hwt_s', 'hwt_s2', 'hwt_Y', 'hwt_deviation',
                          'flow_prediction_list',
                          'flow_prediction_list_total', 'measured_data_list', 'measured_data_list_total',
                          'deviation_list', 'deviation_list_total']:
            if len(gr.graph[parameter]) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:
                gr.graph[parameter].popleft()

        for node_id in gr.nodes():
            gr.node[node_id]['time'].append(0)
            for parameter in ['hwt_addr', 'time', 'hwt_a', 'hwt_s', 'hwt_s2', 'hwt_Y', 'hwt_deviation',
                              'flow_prediction_list',
                              'flow_prediction_list_total', 'measured_data_list', 'measured_data_list_total',
                              'deviation_list', 'deviation_list_total']:
                if len(gr.node[node_id][parameter]) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:
                    gr.node[node_id][parameter].popleft()
        for src, dst in gr.edges():
            gr[src][dst]['time'].append(0)
            for parameter in ['hwt_edge', 'time', 'hwt_a', 'hwt_s', 'hwt_s2', 'hwt_Y', 'hwt_deviation',
                              'flow_prediction_list', 'flow_prediction_list_total', 'measured_data_list',
                              'measured_data_list_total', 'deviation_list', 'deviation_list_total']:
                if len(gr[src][dst][parameter]) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:
                    gr[src][dst][parameter].popleft()

    return gr


def AddRecord(rec, gr, ip_range, next_period, is_learning):
    src_ip = CheckIPRange(str(rec.SRC_IP), ip_range)
    dst_ip = CheckIPRange(str(rec.DST_IP), ip_range)
    gr = FillGraphRecord(gr, rec, next_period)
    gr = NextPeriodProcess(gr, next_period)
    gr = FillNodeRecord(src_ip, rec, gr)
    gr = FillNodeRecord(dst_ip, rec, gr)
    gr = FillEdgeRecord(src_ip, dst_ip, rec, gr)
    return gr


def ParseAdditionalParams(parser):
    options, args = parser.parse_args()
    prop_array = None
    properties = options.properties
    ip_range = options.ip_range
    logger_severity = options.logger_severity.upper()
    plot_interval_periods = options.plot_interval
    whitelist_file_path = options.whitelist_file_path
    if properties is not None:
        prop_array = properties.split(',')

    if ip_range is not None:
        ip_range = ip_range.split('-')
        ip_range = list(ipaddress.summarize_address_range(ipaddress.ip_address(unicode(ip_range[0], "utf-8")),
                                                          ipaddress.ip_address(unicode(ip_range[1], "utf-8"))))
    if plot_interval_periods is not None:
        plot_interval_periods = DAY_PERIODS_COUNT * int(plot_interval_periods)
        if plot_interval_periods < HOUR_PERIODS_COUNT:
            plot_interval_periods = HOUR_PERIODS_COUNT

    return logger_severity, prop_array, ip_range, options.file_path, options.learning, plot_interval_periods, whitelist_file_path


def ExportData(file_path="data"):
    print "Exporting data"
    gr_to_save = nx.DiGraph(gr)
    gr_to_save.graph['flow_count'] = list(gr_to_save.graph['flow_count'])
    gr_to_save.graph['hwt_flow'] = list()
    gr_to_save.graph['hwt_a'] = list(gr_to_save.graph['hwt_a'])
    print len(gr_to_save.graph['hwt_a'])
    gr_to_save.graph['hwt_s'] = list(gr_to_save.graph['hwt_s'])
    gr_to_save.graph['hwt_s2'] = list(gr_to_save.graph['hwt_s2'])
    gr_to_save.graph['hwt_Y'] = list(gr_to_save.graph['hwt_Y'])
    gr_to_save.graph['hwt_deviation'] = list()

    gr_to_save.graph['flow_prediction_list'] = []
    gr_to_save.graph['flow_prediction_list_total'] = []
    gr_to_save.graph['measured_data_list'] = []
    gr_to_save.graph['measured_data_list_total'] = []
    gr_to_save.graph['deviation_list'] = []
    gr_to_save.graph['deviation_list_total'] = []

    for node_id, node_attrs in gr_to_save.nodes(data=True):
        gr_to_save.node[node_id]['permanent_addr'] = True
        for tm in gr_to_save.node[node_id]['time']:
            if tm == 0:
                gr_to_save.node[node_id]['permanent_addr'] = False
                break
        gr_to_save.node[node_id]['time'] = list(node_attrs['time'])
        gr_to_save.node[node_id]['hwt_addr'] = list()
        gr_to_save.node[node_id]['hwt_addr_last'] = 0
        gr_to_save.node[node_id]['hwt_a'] = list(gr_to_save.node[node_id]['hwt_a'])
        gr_to_save.node[node_id]['hwt_s'] = list(gr_to_save.node[node_id]['hwt_s'])
        gr_to_save.node[node_id]['hwt_s2'] = list(gr_to_save.node[node_id]['hwt_s2'])
        gr_to_save.node[node_id]['hwt_Y'] = list(gr_to_save.node[node_id]['hwt_Y'])
        gr_to_save.node[node_id]['hwt_deviation'] = list()

        gr_to_save.node[node_id]['flow_prediction_list'] = list()
        gr_to_save.node[node_id]['flow_prediction_list_total'] = list()
        gr_to_save.node[node_id]['measured_data_list'] = list()
        gr_to_save.node[node_id]['measured_data_list_total'] = list()
        gr_to_save.node[node_id]['deviation_list'] = list()
        gr_to_save.node[node_id]['deviation_list_total'] = list()

    for src, dst, edge_attrs in gr_to_save.edges(data=True):
        gr_to_save[src][dst]['permanent_edge'] = True
        for tm in gr_to_save[src][dst]['time']:
            if tm == 0:
                gr_to_save[src][dst]['permanent_edge'] = False
                break
        gr_to_save[src][dst]['time'] = list(edge_attrs['time'])
        gr_to_save[src][dst]['hwt_edge'] = list()
        gr_to_save[src][dst]['hwt_edge_last'] = 0
        gr_to_save[src][dst]['hwt_a'] = list(gr_to_save[src][dst]['hwt_a'])
        gr_to_save[src][dst]['hwt_s'] = list(gr_to_save[src][dst]['hwt_s'])
        gr_to_save[src][dst]['hwt_s2'] = list(gr_to_save[src][dst]['hwt_s2'])
        gr_to_save[src][dst]['hwt_Y'] = list(gr_to_save[src][dst]['hwt_Y'])
        gr_to_save[src][dst]['hwt_deviation'] = list()

        gr_to_save[src][dst]['flow_prediction_list'] = list()
        gr_to_save[src][dst]['flow_prediction_list_total'] = list()
        gr_to_save[src][dst]['measured_data_list'] = list()
        gr_to_save[src][dst]['measured_data_list_total'] = list()
        gr_to_save[src][dst]['deviation_list'] = list()
        gr_to_save[src][dst]['deviation_list_total'] = list()

    try:
        (filepath, filename) = os.path.split(file_path)
        if filepath:
            if not os.path.exists(filepath):
                os.makedirs(filepath)
        filehandle = open(str(file_path), 'w')
    except IOError:
        print "Can not write data."
        return
    filehandle.write(
        json.dumps(json_graph.node_link_data(gr_to_save), sort_keys=True, indent=2, separators=(',', ': ')))

def TrimImportedData(gr,shift,list_to_shift,type):
    for parameter in list_to_shift:
        if type == "graph":
            gr.graph[parameter].rotate(shift)
        if type == "node":
            for addr in gr.nodes():
                gr.node[addr][parameter].rotate(shift)
        if type == "edge":
            for src,dst in gr.edges():
                gr[src][dst][parameter].rotate(shift)





def ImportData(rec, file_path="data/learned.json"):
    print "Importing data"
    print file_path
    if not os.path.exists(file_path):
        print "Could not find learned data, start with -l parameter first."
        return
    try:
        filehandle = open(str(file_path), 'r')
    except:
        print "Could not find learned data, start with -l parameter first.."
        return

    data = json.loads(filehandle.read())
    graph = json_graph.node_link_graph(data, directed=True, multigraph=False,
                                       attrs={'id': 'id', 'source': 'source', 'target': 'target',
                                              'last_seen': 'last_seen', 'time': 'time', 'hwt_a':'hwt_a',
                                              'hwt_s':'hwt_s','hwt_s2':'hwt_s2','hwt_Y':'hwt_Y','hwt_params':'hwt_params'})
    for src, dst, edge_attrs in graph.edges(data=True):
        graph[src][dst]['permanent_edge'] = True
        graph[src][dst]['time'] = deque(edge_attrs['time'])
        graph[src][dst]['hwt_edge'] = deque()
        graph[src][dst]['hwt_edge_last'] = 0
        graph[src][dst]['hwt_deviation'] = deque([0])
        graph[src][dst]['hwt_a'] = deque(graph[src][dst]['hwt_a'])
        graph[src][dst]['hwt_s'] = deque(graph[src][dst]['hwt_s'])
        graph[src][dst]['hwt_s2'] = deque(graph[src][dst]['hwt_s2'])
        graph[src][dst]['hwt_Y'] = deque(graph[src][dst]['hwt_Y'])

        graph[src][dst]['flow_prediction_list'] = deque()
        graph[src][dst]['flow_prediction_list_total'] = deque()
        graph[src][dst]['measured_data_list'] = deque()
        graph[src][dst]['measured_data_list_total'] = deque()
        graph[src][dst]['deviation_list'] = deque()
        graph[src][dst]['deviation_list_total'] = deque()

        for tm in graph[src][dst]['time']:
            if tm == 0:
                graph[src][dst]['permanent_edge'] = False
                break

    for node_id, node_attrs in graph.nodes(data=True):
        graph.node[node_id]['time'] = deque(node_attrs['time'])
        graph.node[node_id]['permanent_addr'] = True
        graph.node[node_id]['hwt_addr'] = deque()
        graph.node[node_id]['hwt_addr_last'] = 0
        graph.node[node_id]['hwt_a'] = deque(graph.node[node_id]['hwt_a'])
        graph.node[node_id]['hwt_s'] = deque(graph.node[node_id]['hwt_s'])
        graph.node[node_id]['hwt_s2'] = deque(graph.node[node_id]['hwt_s2'])
        graph.node[node_id]['hwt_Y'] = deque(graph.node[node_id]['hwt_Y'])
        graph.node[node_id]['hwt_deviation'] = deque([0])
        graph.node[node_id]['flow_prediction_list'] = deque()
        graph.node[node_id]['flow_prediction_list_total'] = deque()
        graph.node[node_id]['measured_data_list'] = deque()
        graph.node[node_id]['measured_data_list_total'] = deque()
        graph.node[node_id]['deviation_list'] = deque()
        graph.node[node_id]['deviation_list_total'] = deque()
        for tm in graph.node[node_id]['time']:
            if tm == 0:
                graph.node[node_id]['permanent_addr'] = False
                break

    graph.graph['flow_count'] = deque(graph.graph['flow_count'])
    graph.graph['hwt_a'] = deque(graph.graph['hwt_a'])
    graph.graph['hwt_s'] = deque(graph.graph['hwt_s'])
    graph.graph['hwt_s2'] = deque(graph.graph['hwt_s2'])
    graph.graph['hwt_Y'] = deque(graph.graph['hwt_Y'])
    graph.graph['hwt_flow'] =deque()
    graph.graph['hwt_flow_last'] = 0
    graph.graph['hwt_deviation'] = deque([0])
    graph.graph['flow_prediction_list'] = deque()
    graph.graph['flow_prediction_list_total'] = deque()
    graph.graph['measured_data_list'] = deque()
    graph.graph['measured_data_list_total'] = deque()
    graph.graph['deviation_list'] = deque()
    graph.graph['deviation_list_total'] = deque()
    # print graph.graph['last_flow'], rec.TIME_LAST.getSec()
    loaded_interval_index = (graph.graph['last_flow'] / (TIME_WINDOW_SECONDS)) % (WEEK_AGGREGATION_PERIODS_COUNT)
    current_interval_index = (rec.TIME_LAST.getSec() / (TIME_WINDOW_SECONDS)) % (WEEK_AGGREGATION_PERIODS_COUNT)
    time_shift = loaded_interval_index - current_interval_index
    # print graph.graph['flow_count'][-1]

    print "time shift", time_shift
    list_to_shift = ['flow_count', 'hwt_flow', 'hwt_a', 'hwt_s', 'hwt_s2', 'hwt_Y', 'hwt_deviation',
                          'flow_prediction_list',
                          'flow_prediction_list_total', 'measured_data_list', 'measured_data_list_total',
                          'deviation_list', 'deviation_list_total']
    TrimImportedData(graph, time_shift,list_to_shift,"garph")
    list_to_shift = ['hwt_addr', 'time', 'hwt_a', 'hwt_s', 'hwt_s2', 'hwt_Y', 'hwt_deviation',
                              'flow_prediction_list',
                              'flow_prediction_list_total', 'measured_data_list', 'measured_data_list_total',
                              'deviation_list', 'deviation_list_total']
    TrimImportedData(graph, time_shift,list_to_shift,"node")
    list_to_shift = ['hwt_edge', 'time', 'hwt_a', 'hwt_s', 'hwt_s2', 'hwt_Y', 'hwt_deviation',
                              'flow_prediction_list', 'flow_prediction_list_total', 'measured_data_list',
                              'measured_data_list_total', 'deviation_list', 'deviation_list_total']
    TrimImportedData(graph, time_shift,list_to_shift,"edge")
    print "kontrola rotace", loaded_interval_index, current_interval_index, time_shift

    graph.graph['last_flow'] = rec.TIME_LAST.getSec()
    for node_id in graph.nodes():
        graph.node[node_id]['last_seen'] = rec.TIME_LAST.getSec()
    for src, dst in graph.edges():
        graph[src][dst]['last_seen'] = rec.TIME_LAST.getSec()
    return graph


module_info = trap.CreateModuleInfo(
    "GraphFlow",  # Module name
    "Graph representation of local network",  # Description
    1,  # Number of input interfaces
    0,  # Number of output interfaces
    parser  # use previously defined OptionParser
)


def ModuleInitialization():
    # Initialize module
    ifc_spec = trap.parseParams(sys.argv, module_info)
    trap.init(module_info, ifc_spec)
    trap.registerDefaultSignalHandler()  # This is needed to allow module termination using s SIGINT or SIGTERM signal
    # this module accepts all UniRec fieds -> set required format:
    trap.set_required_fmt(0, trap.TRAP_FMT_UNIREC, "")


ModuleInitialization()
gr = FlowProcess(gr)
