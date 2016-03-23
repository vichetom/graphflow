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
NUM_PERIODS_REPORT = 12

##Length of period for graph plotting in hours.
PLOT_INTERVAL_DAYS = 24

##Number of seconds in on period (length of time window in seconds).
TIME_WINDOW_SECONDS = 60 * AGGREGATION_PERIOD_MINUTES

##Size of batch of intervals to be prediceted in every new prediction event.
PREDICTION_INTERVALS = 1

##Decalaration of Holt-Winters deviation constatnt.
HWT_SCALING_FACTOR = 2

##Number of flows during one period dividing traffic to low/high usage.
THRESHOLD = 100

##Parameters accepted by module to be processed.
ALLOWED_PROPERTIES = ["PORT", "BYTES", "PACKETS", "DST_PORT", "SRC_PORT", "HTTP_RSP_CODE", "PROTOCOL", "TCP_FLAGS",
                      "TTL", "TIME_FIRST", "TIME_LAST"]

##Initialization of graph structure
gr = nx.DiGraph(flow_count=deque(), last_flow=0, prediction_count=PREDICTION_INTERVALS, detection_seq=0,
                prediction_sum=0,
                prediction_eval=0, values_last_sum=0, hwt_flow=deque(), hwt_flow_last=0,
                hwt_params=[None, None, None],
                hwt_a=deque(), hwt_s=deque(), hwt_s2=deque(), hwt_Y=deque(), hwt_deviation= deque(), flow_prediction_list=deque(),
                flow_prediction_list_total=deque(),
                measured_data_list=deque(), measured_data_list_total=deque(),deviation_list = deque(),deviation_list_total = deque())

##Initialization of matplotlib figure.
known_node_list = []
known_edges_list = []
unknown_node_list = []
unknown_edges_list = []

plt.figure(figsize=(20, 15))
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
                  dest="logger_severity", default="WARNING",
                  help="Set severity for logger from: info, debug, warning, error")
parser.add_option("-r", "--ip-range",
                  dest="ip_range", default=None,
                  help="Set range of ip addresses in local network first ip-last ip ")
parser.add_option("-g", "--plot-interval",
                  dest="plot_interval",
                  help="Set interval between plotting graphs in hours.")
parser.add_option("-f", "--file-path", dest="file_path",
                  help="Set path of file to save data or load data. Path is relative from actual path. If parameter is not set, default value is data/learned.json",
                  default="data/learned.json")
parser.add_option("-q", "--quiet",
                  action="store_false", dest="verbose", default=True,
                  help="don't print status messages to stdout")


# ------------------------------------------------------


def FlowProcess( gr  ):
    stats_trigger = 0
    rec_buffer = []
    is_first_run = True
    next_period = False
    UR_Flow = None
    plot_interval = 0
    logger_severity, prop_array, ip_range, file_path, is_learning, plot_interval_periods = ParseAdditionalParams(parser)
    LoggerInitialization(logger_severity)
    quiet_period = True


    ## Main loop (trap.stop is set to True when SIGINT or SIGTERM is received)
    while not trap.stop:
        ## Read data from input interface
        rec, UR_Flow = DataLoader(UR_Flow)
        if rec == -1:
            break
        if is_first_run:
            stats_trigger = rec.TIME_LAST.getSec() - (rec.TIME_LAST.getSec() % 60) + (10 * 60)
            if is_learning == False:
                gr = ImportData(rec, file_path)
                known_edge_list = gr.edges()
                print known_edge_list
                known_node_list = gr.nodes()
                gr.graph['prediction_count'] = PREDICTION_INTERVALS
                for node_id in gr.nodes():
                    gr.node[node_id]['prediction_count'] = PREDICTION_INTERVALS
                for src, dst in gr.edges():
                    gr[src][dst]['prediction_count'] = PREDICTION_INTERVALS

        if rec.TIME_LAST.getSec() > stats_trigger:
            next_period = True
            if not is_learning:
                if plot_interval_periods is not None:
                    plot_interval += 1
                    print "plot interval", plot_interval, plot_interval_periods
                FlowAnalysis(gr,  NUM_PERIODS_REPORT)
                NodeAnalysis(gr,  NUM_PERIODS_REPORT)
                EdgeAnalysis(gr,  NUM_PERIODS_REPORT)
                quiet_period = QuietPeriodProcess(gr, THRESHOLD,quiet_period)

        if not is_learning and plot_interval >= plot_interval_periods and plot_interval_periods is not None and TimestampToStr('%H', gr.graph['last_flow']) == "03":
            PlotData(gr,False)
            plot_interval = 0

        gr, is_learning, next_period, stats_trigger, rec_buffer = FillGraph(gr, rec,ip_range, is_learning,prop_array, next_period,
                                                                            stats_trigger, rec_buffer, file_path)

        is_first_run = False

    for record in rec_buffer:
        gr = AddRecord(record, gr, prop_array, ip_range, next_period, is_learning)
        next_period = False
    if len(gr.graph['flow_count']) >= (TWO_WEEK_AGGREGATION_PERIODS_COUNT) and is_learning == True:
        known_node_list = gr.nodes()
        known_edge_list = gr.edges()
        ExportData(file_path)
    PlotData(gr,True)
    return gr


def PlotData (gr,is_total):
    if is_total:
        prediction = "flow_prediction_list_total"
        measured = "measured_data_list_total"
        deviation = "deviation_list_total"

    else:
        prediction = "flow_prediction_list"
        measured = "measured_data_list"
        deviation = "deviation_list"

    for src,dst in gr.edges():
        if gr.edge[src][dst]['permanent_edge']:
            print src,dst
            img_path = "img/flow-"+src+"-"+dst+"/"+TimestampToStr('%Y-%m-%d %H:%M', gr.graph['last_flow'])
            PlotFlow(gr[src][dst][prediction], gr[src][dst][measured],gr[src][dst][deviation],img_path)
            gr.edge[src][dst][prediction] = deque()
            gr.edge[src][dst][measured] = deque()
            gr.edge[src][dst][deviation] = deque()


    for ipaddr in gr.nodes():
        if gr.node[ipaddr]['permanent_addr']:
            print ipaddr
            img_path = "img/ip-"+ipaddr+"/"+TimestampToStr('%Y-%m-%d %H:%M', gr.graph['last_flow'])
            PlotFlow(gr.node[ipaddr][prediction], gr.node[ipaddr][measured],gr.node[ipaddr][deviation],img_path)
            gr.node[ipaddr][prediction] = deque()
            gr.node[ipaddr][measured] = deque()
            gr.node[ipaddr][deviation] = deque()

    img_path = "img/total/"+TimestampToStr('%Y-%m-%d %H:%M', gr.graph['last_flow'])
    PlotFlow(gr.graph[prediction], gr.graph[measured],gr.graph[deviation],img_path)
    PlotGraph(gr,img_path)
    gr.graph['flow_prediction_list'] = deque()
    gr.graph['measured_data_list'] = deque()
    gr.graph['deviation_list'] = deque()

def PlotGraph(gr,img_path):
    node_plot_list = []
    edge_plot_list = []

    try:
        (filepath, filename) = os.path.split(img_path)
        if not os.path.exists(filepath):
            os.makedirs(filepath)
        for node, data in gr.nodes(data=True):
            for count in list(data['time'])[-PLOT_INTERVAL_DAYS*DAY_PERIODS_COUNT:]:
                if count >0:
                    node_plot_list.append(node)
                    break
        for src,dst, data in gr.edges(data=True):
            for count in list(data['time'])[-PLOT_INTERVAL_DAYS*DAY_PERIODS_COUNT:]:
                if count > 0:
                    edge_plot_list.append([src,dst])
                    break
        nx.draw_shell(gr,nodelist=node_plot_list,edgelist=edge_plot_list, arrows=True, with_labels=True)
        print str(img_path) + 'graph.pdf'
        plt.savefig(str(img_path) + 'graph.pdf')

    except IOError:
        print "Can not write image data."
        return
    plt.cla()
    plt.clf()

def PlotFlow(flow_prediction_list, measured_data_list, deviation_list, img_path):
    # print flow_prediction_list, measured_data_list
    interval_low = []
    interval_high = []
    for dev, predicted_value in zip(deviation_list, flow_prediction_list):
        interval_low.append(predicted_value - dev)
        interval_high.append(predicted_value + dev)

    try:
        (filepath, filename) = os.path.split(img_path)
        if not os.path.exists(filepath):
            os.makedirs(filepath)
        plt.plot(measured_data_list, label='prediction data')

        if len(deviation_list) > 0:
            plt.plot(interval_low, label='low interval')
            plt.plot(interval_high, label='high interval')
        else:
            plt.plot(flow_prediction_list, label='real data')
        plt.legend()
        plt.savefig(str(img_path) + '.png')

    except IOError:
        print "Can not write image data."
        return
    plt.cla()
    plt.clf()
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
        print("Negotiation:", fmttype, fmtspec)
        print "Negotiation"
        # Set the same format for output IFC negotiation
        # trap.set_data_fmt(0, fmttype, fmtspec)
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


def EdgeAnalysis(gr,  num_blocks_report):
    for src, dst in gr.edges():


        if [src,dst] not in known_edges_list and [src,dst] not in unknown_edges_list:
            unknown_edges_list.append([src,dst])
            print unknown_edges_list
            logger.anomaly('Unknown connection: %s - %s in time: %s - %s', src, dst,
                               TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen'] - TIME_WINDOW_SECONDS),
                               TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))

        if gr[src][dst]['time'][-1] == 0:
            if gr[src][dst]['time'][-2] != 0 and not gr[src][dst]['permanent_edge']:
                logger.info('Connection: %s - %s disconnected in time: %s', src, dst,
                             TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))
            elif gr[src][dst]['permanent_edge']:
                gr[src][dst]['permanent_edge'] = False
                # print gr.node[src]['permanent_addr'],gr.node[dst]['permanent_addr']
                logger.info('Known connection: %s - %s disconnected in time: %s - %s', src, dst,
                               TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen'] - 300),
                               TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))
        elif gr[src][dst]['time'][-2] == 0:
            logger.info('Connection %s - %s connected in time: %s', src,dst,
                         TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))


        if not 0 in gr[src][dst]['time'] and gr[src][dst]['permanent_edge'] == False:
            gr[src][dst]['permanent_edge'] = True
            gr[src][dst]['prediction_count'] = PREDICTION_INTERVALS
            gr[src][dst]['hwt_edge'] = deque()
            logger.info('New known Connection: %s - %s in last 2 weeks before: %s', src, dst,
                           TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))

        if len(gr[src][dst]['time']) >= (TWO_WEEK_AGGREGATION_PERIODS_COUNT):
            if len(gr[src][dst]['hwt_edge']) > 0 and gr[src][dst]['permanent_edge']:

                if len(gr[src][dst]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                    hwt_flow_deviation = abs(gr[src][dst]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                    gr[src][dst]['deviation_list'].append(gr[src][dst]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                    gr[src][dst]['deviation_list_total'].append(gr[src][dst]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                else:
                    hwt_flow_deviation = abs(gr[src][dst]['hwt_deviation'][-1])
                    gr[src][dst]['deviation_list'].append(gr[src][dst]['hwt_deviation'][-1])
                    gr[src][dst]['deviation_list_total'].append(gr[src][dst]['hwt_deviation'][-1])
                actual_prediction_count = gr[src][dst]['prediction_count']
                gr[src][dst]['flow_prediction_list'].append(gr[src][dst]['hwt_edge'][actual_prediction_count])
                gr[src][dst]['measured_data_list'].append(gr[src][dst]['time'][-1])
                gr[src][dst]['flow_prediction_list_total'].append(gr[src][dst]['hwt_edge'][actual_prediction_count])
                gr[src][dst]['measured_data_list_total'].append(gr[src][dst]['time'][-1])
                if abs(gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][
                    actual_prediction_count]) > hwt_flow_deviation*HWT_SCALING_FACTOR:
                    #print "used edge deviation",hwt_flow_deviation
                    gr[src][dst]['detection_seq'] += 1
                    gr[src][dst]['prediction_sum'] += gr[src][dst]['hwt_edge'][actual_prediction_count]
                    gr[src][dst]['values_last_sum'] += int(gr[src][dst]['time'][-1])
                    if gr[src][dst]['detection_seq'] == num_blocks_report:
                        logger.anomaly('Connection %s - %s flows count: %s prediction: %s per %s miutes during last %s minutes before %s', src, dst,
                                       int(gr[src][dst]['values_last_sum'] / num_blocks_report),
                                       int(gr[src][dst]['prediction_sum'] / num_blocks_report),
                                       AGGREGATION_PERIOD_MINUTES,
                                       num_blocks_report * AGGREGATION_PERIOD_MINUTES,
                                       TimestampToStr('%Y-%m-%d %H:%M', gr[src][dst]['last_seen']))
                        gr[src][dst]['detection_seq'] = 0
                        gr[src][dst]['prediction_sum'] = 0
                        gr[src][dst]['values_last_sum'] = 0

                    #gr[src][dst]['time'][-1] = gr[src][dst]['hwt_edge'][actual_prediction_count]

                    gr[src][dst]['hwt_a'].pop()
                    gr[src][dst]['hwt_s'].pop()
                    gr[src][dst]['hwt_s2'].pop()
                    gr[src][dst]['hwt_edge'][-1], gr[src][dst]['hwt_a'], gr[src][dst]['hwt_s'], gr[src][dst][
                                            'hwt_s2'] = hwt.HWTStep(gr[src][dst]['hwt_edge_last'], gr[src][dst]['hwt_a'],
                                            gr[src][dst]['hwt_s'], gr[src][dst]['hwt_s2'],
                                            gr[src][dst]['hwt_params'][0], gr[src][dst]['hwt_params'][1],
                                            gr[src][dst]['hwt_params'][2], DAY_PERIODS_COUNT,
                                            WEEK_AGGREGATION_PERIODS_COUNT, )
                    if len( gr[src][dst]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                        gr[src][dst]['hwt_deviation'][-1] = gr[src][dst]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT]
                    elif len( gr[src][dst]['hwt_deviation']) > 1:
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
                        gr[src][dst]['hwt_deviation'].append(abs(gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][-1]))



                    else:
                        if len(gr[src][dst]['hwt_edge']) > 0:
                            if len(gr[src][dst]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                                gr[src][dst]['hwt_deviation'].append(abs((gr[src][dst]['hwt_params'][1] * (gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][-1])) + ((1 - gr[src][dst]['hwt_params'][1]) * gr[src][dst]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])))
                            else:
                                gr[src][dst]['hwt_deviation'].append(abs((gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][-1])))

                        gr[src][dst]['hwt_edge'][-1], gr[src][dst]['hwt_a'], gr[src][dst]['hwt_s'], gr[src][dst][
                            'hwt_s2'] = hwt.HWTStep(gr[src][dst]['time'][-1], gr[src][dst]['hwt_a'],
                                                    gr[src][dst]['hwt_s'], gr[src][dst]['hwt_s2'],
                                                    gr[src][dst]['hwt_params'][0], gr[src][dst]['hwt_params'][1],
                                                    gr[src][dst]['hwt_params'][2], DAY_PERIODS_COUNT,
                                                    WEEK_AGGREGATION_PERIODS_COUNT, )


def NodeAnalysis(gr,  num_blocks_report):
    for node_id in gr.nodes():
        if node_id not in known_node_list and node_id not in unknown_node_list:
            unknown_node_list.append(node_id)
            logger.anomaly('Unknown IP address: %s in time: %s - %s', node_id,
                               TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen'] - TIME_WINDOW_SECONDS),
                               TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))

        if gr.node[node_id]['time'][-1] == 0:
            if gr.node[node_id]['time'][-2] != 0 and gr.node[node_id]['permanent_addr'] == False:
                logger.info('IP address: %s disconnected in time: %s', node_id,
                             TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))
            elif gr.node[node_id]['permanent_addr']:
                gr.node[node_id]['permanent_addr'] = False
                logger.info('Known IP address: %s disconnected in time: %s - %s', node_id,
                               TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen'] - TIME_WINDOW_SECONDS),
                               TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))
        elif gr.node[node_id]['time'][-2] == 0:
            logger.info('IP address: %s connected in time: %s', node_id,
                         TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))

        if not 0 in gr.node[node_id]['time'] and gr.node[node_id]['permanent_addr'] == False:
            gr.node[node_id]['permanent_addr'] = True
            gr.node[node_id]['prediction_count'] = PREDICTION_INTERVALS
            gr.node[node_id]['hwt_addr'] = deque()
            logger.info('New known IP address: %s in last 2 weeks before:%s', node_id,
                           TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))

        if len(gr.node[node_id]['time']) >= TWO_WEEK_AGGREGATION_PERIODS_COUNT:
            if len(gr.node[node_id]['hwt_addr']) > 0 and gr.node[node_id]['permanent_addr'] == True:
                if len(gr.node[node_id]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                    hwt_flow_deviation = abs(gr.node[node_id]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                    gr.node[node_id]['deviation_list'].append(gr.node[node_id]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                    gr.node[node_id]['deviation_list_total'].append(gr.node[node_id]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                else:
                    hwt_flow_deviation = abs(gr.node[node_id]['hwt_deviation'][-1])
                    gr.node[node_id]['deviation_list'].append(gr.node[node_id]['hwt_deviation'][-1])
                    gr.node[node_id]['deviation_list_total'].append(gr.node[node_id]['hwt_deviation'][-1])
                actual_prediction_count = gr.node[node_id]['prediction_count']
                gr.node[node_id]['flow_prediction_list'].append(gr.node[node_id]['hwt_addr'][actual_prediction_count])
                gr.node[node_id]['measured_data_list'].append(gr.node[node_id]['time'][-1])
                gr.node[node_id]['flow_prediction_list_total'].append(gr.node[node_id]['hwt_addr'][actual_prediction_count])
                gr.node[node_id]['measured_data_list_total'].append(gr.node[node_id]['time'][-1])
                if abs(gr.node[node_id]['time'][-1] - gr.node[node_id]['hwt_addr'][
                    actual_prediction_count]) > hwt_flow_deviation*HWT_SCALING_FACTOR:
                    #print "used node deviation",hwt_flow_deviation
                    gr.node[node_id]['detection_seq'] += 1
                    gr.node[node_id]['prediction_sum'] += gr.node[node_id]['hwt_addr'][actual_prediction_count]
                    gr.node[node_id]['values_last_sum'] += int(gr.node[node_id]['time'][-1])
                    if gr.node[node_id]['detection_seq'] == num_blocks_report:
                        logger.anomaly(
                            'IP %s flows count:%s prediction:%s per %s miutes during last %s minutes before %s', node_id,
                            int(gr.node[node_id]['values_last_sum'] / num_blocks_report),
                            int(gr.node[node_id]['prediction_sum'] / num_blocks_report),
                            AGGREGATION_PERIOD_MINUTES,
                            num_blocks_report * AGGREGATION_PERIOD_MINUTES,
                            TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))
                        gr.node[node_id]['detection_seq'] = 0
                        gr.node[node_id]['prediction_sum'] = 0
                        gr.node[node_id]['values_last_sum'] = 0
                    #gr.node[node_id]['time'][-1] = gr.node[node_id]['hwt_addr'][actual_prediction_count]
                    gr.node[node_id]['hwt_a'].pop()
                    gr.node[node_id]['hwt_s'].pop()
                    gr.node[node_id]['hwt_s2'].pop()

                    gr.node[node_id]['hwt_addr'][-1], gr.node[node_id]['hwt_a'], gr.node[node_id]['hwt_s'], gr.node[node_id][
                                            'hwt_s2'] = hwt.HWTStep(gr.node[node_id]['hwt_addr_last'], gr.node[node_id]['hwt_a'],
                                            gr.node[node_id]['hwt_s'], gr.node[node_id]['hwt_s2'],
                                            gr.node[node_id]['hwt_params'][0], gr.node[node_id]['hwt_params'][1],
                                            gr.node[node_id]['hwt_params'][2], DAY_PERIODS_COUNT,
                                            WEEK_AGGREGATION_PERIODS_COUNT, )
                    if len( gr.node[node_id]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                        gr.node[node_id]['hwt_deviation'][-1] = gr.node[node_id]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT]
                    elif len( gr.node[node_id]['hwt_deviation']) > 1:
                        gr.node[node_id]['hwt_deviation'][-1] = gr.node[node_id]['hwt_deviation'][-2]

                else:
                    gr.node[node_id]['detection_seq'] = 0
                    gr.node[node_id]['prediction_sum'] = 0
                    gr.node[node_id]['values_last_sum'] = 0
                gr.node[node_id]['prediction_count'] += 1

            if gr.node[node_id]['prediction_count'] >= PREDICTION_INTERVALS:
                if len(gr.node[node_id]['hwt_addr']):
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
                        gr.node[node_id]['hwt_deviation'].append(abs(gr.node[node_id]['time'][-1] -  gr.node[node_id]['hwt_addr'][-1]))



                    else:

                        if len(gr.node[node_id]['hwt_addr']) > 0:
                            if len( gr.node[node_id]['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                                 gr.node[node_id]['hwt_deviation'].append(abs((gr.node[node_id]['hwt_params'][1] * ( gr.node[node_id]['time'][-1] -  gr.node[node_id]['hwt_addr'][-1])) + ((1 -  gr.node[node_id]['hwt_params'][1]) *  gr.node[node_id]['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])))
                            else:
                                 gr.node[node_id]['hwt_deviation'].append(abs(( gr.node[node_id]['time'][-1] -  gr.node[node_id]['hwt_addr'][-1])))


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
            actual_prediction_count = gr.graph['prediction_count']
            if len(gr.graph['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                hwt_flow_deviation = abs(gr.graph['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                gr.graph['deviation_list'].append(gr.graph['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                gr.graph['deviation_list_total'].append(gr.graph['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])

            else:
                hwt_flow_deviation = abs(gr.graph['hwt_deviation'][-1])
                gr.graph['deviation_list'].append(gr.graph['hwt_deviation'][-1])
                gr.graph['deviation_list_total'].append(gr.graph['hwt_deviation'][-1])

            gr.graph['flow_prediction_list'].append(gr.graph['hwt_flow'][actual_prediction_count])
            gr.graph['measured_data_list'].append(gr.graph['flow_count'][-1])
            gr.graph['flow_prediction_list_total'].append(gr.graph['hwt_flow'][actual_prediction_count])
            gr.graph['measured_data_list_total'].append(gr.graph['flow_count'][-1])


            if abs(gr.graph['flow_count'][-1] - gr.graph['hwt_flow'][actual_prediction_count]) > hwt_flow_deviation*HWT_SCALING_FACTOR:
                #print "used flow deviation",hwt_flow_deviation
                gr.graph['detection_seq'] += 1
                gr.graph['prediction_sum'] += gr.graph['hwt_flow'][actual_prediction_count]
                gr.graph['values_last_sum'] += int(gr.graph['flow_count'][-1])
                if gr.graph['detection_seq'] == num_blocks_report:
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
                if len( gr.graph['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                    gr.graph['hwt_deviation'][-1] = gr.graph['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT]
                elif len( gr.graph['hwt_deviation']) > 1:
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
                    gr.graph['hwt_flow'], gr.graph['hwt_params'], _, gr.graph['hwt_a'], gr.graph['hwt_s'], gr.graph[
                        'hwt_s2'], gr.graph['hwt_Y'] = hwt.HWT(list(gr.graph['flow_count']), DAY_PERIODS_COUNT,
                                                               WEEK_AGGREGATION_PERIODS_COUNT, PREDICTION_INTERVALS,
                                                               alpha=gr.graph['hwt_params'][0],
                                                               gamma=gr.graph['hwt_params'][1],
                                                               delta=gr.graph['hwt_params'][2],
                                                               initial_values_optimization=[0.5, 0.5, 0.5])

                    gr.graph['hwt_flow_last'] = gr.graph['hwt_flow'][-1]
                    gr.graph['hwt_deviation'].append(abs(gr.graph['flow_count'][-1] -  gr.graph['hwt_flow'][-1]))

                else:
                    if len(gr.graph['hwt_flow']) > 0:
                        if len( gr.graph['hwt_deviation']) >= WEEK_AGGREGATION_PERIODS_COUNT:
                            gr.graph['hwt_deviation'].append(abs((gr.graph['hwt_params'][1] * ( gr.graph['flow_count'][-1] -  gr.graph['hwt_flow'][-1])) + ((1 -  gr.graph['hwt_params'][1]) *  gr.graph['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])))
                            print  gr.graph['flow_count'][-1], gr.graph['hwt_flow'][-1],(gr.graph['hwt_params'][1] * ( gr.graph['flow_count'][-1] -  gr.graph['hwt_flow'][-1])), ((1 -  gr.graph['hwt_params'][1]) *  gr.graph['hwt_deviation'][-WEEK_AGGREGATION_PERIODS_COUNT])
                        else:
                            gr.graph['hwt_deviation'].append(abs( gr.graph['flow_count'][-1] -  gr.graph['hwt_flow'][-1]))

                    gr.graph['hwt_flow'][-1], gr.graph['hwt_a'], gr.graph['hwt_s'], gr.graph['hwt_s2'] = hwt.HWTStep(
                        gr.graph['flow_count'][-1], gr.graph['hwt_a'], gr.graph['hwt_s'], gr.graph['hwt_s2'],
                        gr.graph['hwt_params'][0], gr.graph['hwt_params'][1], gr.graph['hwt_params'][2],
                        DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT, )


def QuietPeriodProcess(gr, threshold,quiet_period):
    all_quiet = True
    all_peak = True
    for count in list(gr.graph['flow_count'])[-12:-2]:
        if count < threshold:
            all_peak = False
        else:
            all_quiet = False

    if all_peak and gr.graph['flow_count'][-1] < threshold and not quiet_period:
        logger.info('Low traffic period started with %s flows per five minutes in time %s', gr.graph['flow_count'][-1],TimestampToStr('%Y-%m-%d %H:%M', gr.graph['last_flow']))
        quiet_period = True
    elif all_quiet and gr.graph['flow_count'][-1] > threshold and quiet_period:
        logger.info('High traffic period started with %s flows per five minutes in time %s', gr.graph['flow_count'][-1],TimestampToStr('%Y-%m-%d %H:%M', gr.graph['last_flow']))
        quiet_period = False
    return quiet_period

def StrToDatetime(time_str, time_format):
    return datetime.datetime.strptime(time_str, time_format)


def TimestampToStr(time_format, timestamp):
    return time.strftime(time_format, time.gmtime(timestamp))


def UpdateParameters(src_ip, dst_ip, rec, properties):
    for p in properties:
        str(getattr(rec, p))
        if p in gr.edge[src_ip][dst_ip]:
            if not str(getattr(rec, p)) in gr.edge[src_ip][dst_ip][p]:
                gr.edge[src_ip][dst_ip][p][str(getattr(rec, p))] = 1
            else:
                gr.edge[src_ip][dst_ip][p][str(getattr(rec, p))] = gr.edge[src_ip][dst_ip][p][str(getattr(rec, p))] + 1

        else:
            gr.edge[src_ip][dst_ip][p] = {}
            gr.edge[src_ip][dst_ip][p][str(getattr(rec, p))] = 1
            # print gr.edge[src_ip][dst_ip][p]
    return gr


def CheckIPRange(ip, ip_range):
    if ip_range is not None:
        if not any(ipaddress.ip_address(unicode(ip, "utf-8")) in p for p in ip_range):
            ip = "0.0.0.0"

    return ip


def FillGraph(gr, rec, ip_range,is_learning, prop_array, next_period, stats_trigger, rec_buffer, file_path):
    if next_period:
        stats_trigger += TIME_WINDOW_SECONDS
        for record in rec_buffer:
            gr = AddRecord(record, gr, prop_array, ip_range, next_period, is_learning)
            next_period = False
        if len(gr.graph['flow_count']) >= TWO_WEEK_AGGREGATION_PERIODS_COUNT and is_learning == True:
            is_learning = False
            known_edge_list = gr.edges()
            known_node_list = gr.nodes()
            ExportData(file_path)
        rec_buffer = []
        rec_buffer.append(rec)
    elif rec.TIME_LAST.getSec() > stats_trigger - TIME_WINDOW_SECONDS:
        rec_buffer.append(rec)
    elif rec.TIME_LAST.getSec() <= stats_trigger - TIME_WINDOW_SECONDS:
        gr = AddRecord(rec, gr, prop_array, ip_range, next_period, is_learning)
        next_period = False
    return gr, is_learning, next_period, stats_trigger, rec_buffer


def FillGraphRecord(gr, rec, next_period):
    if next_period or len(gr.graph['flow_count']) == 0:
        gr.graph['flow_count'].append(1)
    else:
        gr.graph['flow_count'][-1] += 1
    gr.graph['last_flow'] = rec.TIME_LAST.getSec()

    return gr


def FillEdgeRecord(next_period, src_ip, dst_ip, rec, gr, properties, is_learning):
    if gr.has_edge(src_ip, dst_ip):
        gr[src_ip][dst_ip]['last_seen'] = rec.TIME_LAST.getSec()
        gr[src_ip][dst_ip]['time'][-1] += 1
        if properties is not None:
            gr = UpdateParameters(src_ip, dst_ip, rec, properties)
    else:
        if is_learning == False:
            logger.anomaly('Unknown connection: %s - %s in time: %s', src_ip, dst_ip,
                           TimestampToStr('%Y-%m-%d %H:%M', rec.TIME_LAST.getSec()))
        gr.add_edge(src_ip, dst_ip, permanent_edge=False, detection_seq=0,
                    prediction_count=PREDICTION_INTERVALS, hwt_edge=deque(), hwt_edge_last=0,
                    hwt_params=[None, None, None], values_last_sum=0, prediction_sum=0,
                    prediction_eval=0, last_seen=rec.TIME_LAST.getSec(), time=deque(), hwt_a=deque(), hwt_s=deque(),
                    hwt_s2=deque(), hwt_Y=deque(),hwt_deviation= deque(), flow_prediction_list=deque(),flow_prediction_list_total=deque(), measured_data_list=deque(), measured_data_list_total=deque(),
                    deviation_list = deque(), deviation_list_total = deque())
        print gr[src_ip][dst_ip]['hwt_params']
        while len(gr[src_ip][dst_ip]['time']) < len(gr.graph['flow_count']) - 1:
            gr[src_ip][dst_ip]['time'].append(0)
        gr[src_ip][dst_ip]['time'].append(1)
        if properties is not None:
            gr = UpdateParameters(src_ip, dst_ip, rec, properties)
    return gr


def FillNodeRecord(next_period, ip, rec, gr, is_learning):
    if gr.has_node(ip):
        gr.node[ip]['last_seen'] = rec.TIME_LAST.getSec()
        gr.node[ip]['time'][-1] += 1
    else:
        if is_learning == False:
            unknown_node_list.append([ip])
            print "new ip ", ip
            logger.anomaly('Unknown IP address: %s in time: %s', ip,
                           TimestampToStr('%Y-%m-%d %H:%M', rec.TIME_LAST.getSec()))
        gr.add_node(ip, permanent_addr=False, detection_seq=0, prediction_count=PREDICTION_INTERVALS,
                    hwt_addr=deque(), hwt_addr_last=0, hwt_params=[None, None, None], values_last_sum=0,
                    prediction_sum=0, prediction_eval=0,
                    last_seen=rec.TIME_LAST.getSec(), time=deque(), hwt_a=deque(), hwt_s=deque(), hwt_s2=deque(),
                    hwt_Y=deque(),hwt_deviation= deque(),flow_prediction_list=deque(),flow_prediction_list_total=deque(), measured_data_list=deque(), measured_data_list_total=deque(),
                    deviation_list = deque(), deviation_list_total = deque())
        while len(gr.node[ip]['time']) < len(gr.graph['flow_count']) - 1:
            gr.node[ip]['time'].append(0)
        gr.node[ip]['time'].append(1)

    return gr


def NextPeriodProcess(gr, next_period):
    if next_period:
        for parameter in ['flow_count','hwt_flow','hwt_a', 'hwt_s', 'hwt_s2', 'hwt_Y', 'hwt_deviation', 'flow_prediction_list',
                          'flow_prediction_list_total','measured_data_list', 'measured_data_list_total','deviation_list','deviation_list_total']:
            if len(gr.graph[parameter])>TWO_WEEK_AGGREGATION_PERIODS_COUNT:
                print parameter
                gr.graph[parameter].popleft()

        for node_id in gr.nodes():
            gr.node[node_id]['time'].append(0)
            for parameter in ['hwt_addr', 'time', 'hwt_a', 'hwt_s', 'hwt_s2','hwt_Y','hwt_deviation','flow_prediction_list',
                              'flow_prediction_list_total', 'measured_data_list', 'measured_data_list_total',
                              'deviation_list', 'deviation_list_total']:
                if len(gr.node[node_id][parameter]) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:

                    gr.node[node_id][parameter].popleft()
        for src, dst in gr.edges():
            gr[src][dst]['time'].append(0)
            for parameter in ['hwt_edge', 'time', 'hwt_a', 'hwt_s','hwt_s2', 'hwt_Y','hwt_deviation', 'flow_prediction_list','flow_prediction_list_total', 'measured_data_list',
                              'measured_data_list_total','deviation_list','deviation_list_total']:
                if len(gr[src][dst][parameter]) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:

                    gr[src][dst][parameter].popleft()

    return gr


def AddRecord(rec, gr, properties, ip_range, next_period, is_learning):
    src_ip = CheckIPRange(str(rec.SRC_IP), ip_range)
    dst_ip = CheckIPRange(str(rec.DST_IP), ip_range)
    gr = FillGraphRecord(gr, rec, next_period)
    gr = NextPeriodProcess(gr, next_period)
    gr = FillNodeRecord(next_period, src_ip, rec, gr, is_learning)
    gr = FillNodeRecord(next_period, dst_ip, rec, gr, is_learning)
    gr = FillEdgeRecord(next_period, src_ip, dst_ip, rec, gr, properties, is_learning)
    return gr


def ParseAdditionalParams(parser):
    options, args = parser.parse_args()
    prop_array = None
    properties = options.properties
    ip_range = options.ip_range
    logger_severity = options.logger_severity.upper()
    plot_interval_periods = options.plot_interval
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

    return logger_severity, prop_array, ip_range, options.file_path, options.learning, plot_interval_periods



def ExportData(file_path="data"):
    print "Exporting data"
    gr_to_save = nx.DiGraph(gr)
    gr_to_save.graph['flow_count'] = list(gr_to_save.graph['flow_count'])
    gr_to_save.graph['hwt_flow'] = []
    gr_to_save.graph['hwt_params'] = [None, None, None]
    gr_to_save.graph['hwt_a'] = []
    gr_to_save.graph['hwt_s'] = []
    gr_to_save.graph['hwt_s2'] = []
    gr_to_save.graph['hwt_Y'] = []
    gr_to_save.graph['hwt_deviation'] = []

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
        gr_to_save.node[node_id]['hwt_addr'] = []
        gr_to_save.node[node_id]['hwt_addr_last'] = 0
        gr_to_save.node[node_id]['hwt_params'] = [None, None, None]
        gr_to_save.node[node_id]['hwt_a'] = []
        gr_to_save.node[node_id]['hwt_s'] = []
        gr_to_save.node[node_id]['hwt_s2'] = []
        gr_to_save.node[node_id]['hwt_Y'] = []
        gr_to_save.node[node_id]['hwt_deviation'] = []

        gr_to_save.node[node_id]['flow_prediction_list'] = []
        gr_to_save.node[node_id]['flow_prediction_list_total'] = []
        gr_to_save.node[node_id]['measured_data_list'] = []
        gr_to_save.node[node_id]['measured_data_list_total'] = []
        gr_to_save.node[node_id]['deviation_list'] = []
        gr_to_save.node[node_id]['deviation_list_total'] = []


    for src, dst, edge_attrs in gr_to_save.edges(data=True):
        gr_to_save[src][dst]['permanent_edge'] = True
        for tm in gr_to_save[src][dst]['time']:
            if tm == 0:
                gr_to_save[src][dst]['permanent_edge'] = False
                break
        gr_to_save[src][dst]['time'] = list(edge_attrs['time'])
        gr_to_save[src][dst]['hwt_edge'] = []
        gr_to_save[src][dst]['hwt_edge_last'] = 0
        gr_to_save[src][dst]['hwt_params'] = [None, None, None]
        gr_to_save[src][dst]['hwt_a'] = []
        gr_to_save[src][dst]['hwt_s'] = []
        gr_to_save[src][dst]['hwt_s2'] = []
        gr_to_save[src][dst]['hwt_Y'] = []
        gr_to_save[src][dst]['hwt_deviation'] = []

        gr_to_save[src][dst]['flow_prediction_list'] = []
        gr_to_save[src][dst]['flow_prediction_list_total'] = []
        gr_to_save[src][dst]['measured_data_list'] = []
        gr_to_save[src][dst]['measured_data_list_total'] = []
        gr_to_save[src][dst]['deviation_list'] = []
        gr_to_save[src][dst]['deviation_list_total'] = []


    try:
        (filepath, filename) = os.path.split(file_path)
        if not os.path.exists(filepath):
            os.makedirs(filepath)
        filehandle = open(str(file_path), 'w')
    except IOError:
        print "Can not write data."
        return
    filehandle.write(
        json.dumps(json_graph.node_link_data(gr_to_save), sort_keys=True, indent=2, separators=(',', ': ')))


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
                                              'last_seen': 'last_seen', 'time': 'time'})
    for src, dst, edge_attrs in graph.edges(data=True):
        graph[src][dst]['permanent_edge'] = True
        graph[src][dst]['time'] = deque(edge_attrs['time'])
        graph[src][dst]['hwt_edge'] = deque()
        graph[src][dst]['hwt_edge_last'] = 0
        graph[src][dst]['hwt_deviation'] = deque()
        graph[src][dst]['hwt_a'] = deque()
        graph[src][dst]['hwt_s'] = deque()
        graph[src][dst]['hwt_s2'] = deque()
        graph[src][dst]['hwt_Y'] = deque()

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
        graph.node[node_id]['hwt_a'] = deque()
        graph.node[node_id]['hwt_s'] = deque()
        graph.node[node_id]['hwt_s2'] = deque()
        graph.node[node_id]['hwt_Y'] = deque()
        graph.node[node_id]['hwt_deviation'] = deque()
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

    graph.graph['hwt_a'] = deque()
    graph.graph['hwt_s'] = deque()
    graph.graph['hwt_s2'] = deque()
    graph.graph['hwt_Y'] = deque()
    graph.graph['hwt_flow'] = deque()
    graph.graph['hwt_flow_last'] = 0
    graph.graph['hwt_deviation'] = deque()
    graph.graph['flow_prediction_list'] = deque()
    graph.graph['flow_prediction_list_total'] = deque()
    graph.graph['measured_data_list'] = deque()
    graph.graph['measured_data_list_total'] = deque()
    graph.graph['deviation_list'] = deque()
    graph.graph['deviation_list_total'] = deque()
    # print graph.graph['last_flow'], rec.TIME_LAST.getSec()
    loaded_interval_index = (graph.graph['last_flow'] / (TIME_WINDOW_SECONDS)) % (WEEK_AGGREGATION_PERIODS_COUNT)
    actual_interval_index = (rec.TIME_LAST.getSec() / (TIME_WINDOW_SECONDS)) % (WEEK_AGGREGATION_PERIODS_COUNT)
    time_shift = loaded_interval_index - actual_interval_index
    # print graph.graph['flow_count'][-1]
    graph.graph['flow_count'] = deque(graph.graph['flow_count'])
    print "time shift", time_shift
    graph.graph['flow_count'].rotate(time_shift)
    for node_id in graph.nodes():
        graph.node[node_id]['time'].rotate(time_shift)
    for src, dst in graph.edges():
        graph[src][dst]['time'].rotate(time_shift)
    print "kontrola rotace", loaded_interval_index, actual_interval_index, time_shift
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
    # Specifier of UniRec records will be received during libtrap negotiation


ModuleInitialization()
gr = FlowProcess( gr )
