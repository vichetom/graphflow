#!/usr/bin/python

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









AGGREGATION_PERIOD_MINUTES = 5
HOUR_PERIODS_COUNT = 60/AGGREGATION_PERIOD_MINUTES
DAY_PERIODS_COUNT = 24 * HOUR_PERIODS_COUNT
WEEK_AGGREGATION_PERIODS_COUNT = 7 * DAY_PERIODS_COUNT
TWO_WEEK_AGGREGATION_PERIODS_COUNT = 2 * WEEK_AGGREGATION_PERIODS_COUNT
NUM_PERIODS_REPORT = 12
PLOT_INTERVAL_HOURS = 24
TIME_WINDOW_SECONDS = 60 * AGGREGATION_PERIOD_MINUTES
PREDICTION_INTERVALS = 1
THRESHOLD = 100
ALLOWED_PROPERTIES = ["PORT", "BYTES", "PACKETS", "DST_PORT", "SRC_PORT", "HTTP_RSP_CODE", "PROTOCOL", "TCP_FLAGS",
                      "TTL", "TIME_FIRST", "TIME_LAST"]
gr = nx.DiGraph(flow_count=deque(),last_flow=0,prediction_count = PREDICTION_INTERVALS,detection_seq = 0,prediction_sum = 0,prediction_eval = 0,values_lasts = deque(), hwt_flow = deque(),hwt_flow_last = deque(),hwt_params = [None,None,None],hwt_a = deque(),hwt_s = deque(),hwt_s2 = deque(),hwt_Y =[])
hwt_deviation = 0
properties = None
prop_array = None
ip_range = None
plot_interval_periods = HOUR_PERIODS_COUNT * PLOT_INTERVAL_HOURS
is_learning = False
hwt_flow_deviation = 100
logger = logging.getLogger(__name__)
handler = logging.FileHandler('graphflow.log' + str(datetime.datetime.now()))
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

# How to add options of module
from optparse import OptionParser

parser = OptionParser(add_help_option=False)
parser.add_option("-l", "--learning",
                  action="store_true", dest="learning", default=False,
                  help="Turns learning phase on and off. Choose True/False")
parser.add_option("-p", "--properties",
                  dest="properties", default=None,
                  help="Set properties to be saved. Separated by comma. Its possible to choose from: " + str(
                      ALLOWED_PROPERTIES))
parser.add_option("-r", "--ip-range",
                  dest="ip_range", default=None,
                  help="Set range of ip addresses in local network first ip-last ip ")
parser.add_option("-e", "--export-interval",
                  dest="export_interval", default=60,
                  help="Set data export interval. Default is 60 sec.")
parser.add_option("-d", "--directory", dest="directory",
                  help="Set directory to save data. If parameter is not set, data are not saved.", metavar="FILE")
parser.add_option("-q", "--quiet",
                  action="store_false", dest="verbose", default=True,
                  help="don't print status messages to stdout")


# ------------------------------------------------------


def FlowProcess(is_learning, gr, prop_array, ip_range):
    stats_trigger = 0
    rec_buffer = []
    is_first_run = True
    next_period = False
    flow_prediction_list = []
    flow_prediction_list_total = []
    measured_data_list = []
    measured_data_list_total = []
    plot_interval = 0
    UR_Flow = None

    ## Main loop (trap.stop is set to True when SIGINT or SIGTERM is received)
    while not trap.stop:
        ## Read data from input interface
        rec,UR_Flow = DataLoader(UR_Flow)
        if rec == -1:
            break
        if is_first_run:
            stats_trigger = rec.TIME_LAST.getSec() - (rec.TIME_LAST.getSec() % 60) + (10 * 60)
            if is_learning == False:
                gr = ImportData(rec, )
                gr.graph['prediction_count'] = PREDICTION_INTERVALS
                for node_id in gr.nodes():
                    gr.node[node_id]['prediction_count'] = PREDICTION_INTERVALS
                for src, dst in gr.edges():
                    gr[src][dst]['prediction_count'] = PREDICTION_INTERVALS

        if rec.TIME_LAST.getSec() > stats_trigger:
            next_period = True
            if not is_learning:
                plot_interval += 1
                FlowAnalysis(gr, hwt_flow_deviation, NUM_PERIODS_REPORT, flow_prediction_list, measured_data_list,
                             flow_prediction_list_total, measured_data_list_total)
                NodeAnalysis(gr, hwt_flow_deviation, NUM_PERIODS_REPORT)
                EdgeAnalysis(gr, hwt_flow_deviation, NUM_PERIODS_REPORT)
                QuietPeriodProcess(gr,THRESHOLD)

        if not is_learning and plot_interval == plot_interval_periods:
            # print flow_prediction_list,measured_data_list
            PlotFlow(flow_prediction_list, measured_data_list, TimestampToStr('%Y-%m-%d %H:%M',gr.graph['last_flow']))
            plot_interval = 0
            flow_prediction_list = []
            measured_data_list = []
            plt.clf()

        gr, is_learning, next_period,stats_trigger,rec_buffer = FillGraph(gr, rec, is_learning, next_period,stats_trigger,rec_buffer,directory)
        is_first_run = False


    for record in rec_buffer:
        gr = AddRecord(record, gr, prop_array, ip_range, next_period,  is_learning)
        next_period = False
    if len(gr.graph['flow_count']) >= (TWO_WEEK_AGGREGATION_PERIODS_COUNT) and is_learning == True:
        is_learning = False
        ExportData(directory)
    #print len(gr.graph['flow_count']), (TWO_WEEK_AGGREGATION_PERIODS_COUNT), gr.nodes(), next_period, gr.graph['last_flow']
    PlotFlow(flow_prediction_list_total, measured_data_list_total, TimestampToStr('%Y-%m-%d %H:%M',gr.graph['last_flow']))
    return gr


def PlotFlow(flow_prediction_list, measured_data_list, name):
    plt.figure(figsize=(20, 15))
    #print flow_prediction_list, measured_data_list
    plt.plot(flow_prediction_list, label='prediction data')
    plt.plot(measured_data_list, label='real data')
    plt.legend()
    plt.savefig(str(name) + 'prediction.png')
    plt.clf()
    print "plotting deleting"

def DataLoader(UR_Flow):
    try:
        data = trap.recv(0)
    except trap.EFMTMismatch:
        print("Error: output and input interfaces data format or data specifier mismatch")
        return -1,-1
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
        return -1,-1

    # Check for "end-of-stream" record
    if len(data) <= 1:
        return -1,-1

    return UR_Flow(data), UR_Flow

def EdgeAnalysis(gr, hwt_flow_deviation, num_blocks_report):
    for src, dst in gr.edges():
        if gr[src][dst]['time'][-1] == 0:
            if gr[src][dst]['time'][-2] != 0 and gr[src][dst]['permanent_edge'] == False:
                logger.debug('Connection from: %s to: %s disconnected in time: %s', src, dst, TimestampToStr('%Y-%m-%d %H:%M',gr[src][dst]['last_seen']))
            elif gr[src][dst]['permanent_edge'] == True:
                gr[src][dst]['permanent_edge'] = False
                # print gr.node[src]['permanent_addr'],gr.node[dst]['permanent_addr']
                logger.warning('Permanent connection from: %s to: %s disconnected in time: %s - %s', src, dst, TimestampToStr('%Y-%m-%d %H:%M',gr[src][dst]['last_seen'] - 300),
                               TimestampToStr('%Y-%m-%d %H:%M',gr[src][dst]['last_seen']))

        if not 0 in gr[src][dst]['time'] and gr[src][dst]['permanent_edge'] == False:
            gr[src][dst]['permanent_edge'] = True
            gr[src][dst]['prediction_count'] = PREDICTION_INTERVALS
            gr[src][dst]['hwt_edge'] = deque()
            logger.warning('New permanent connection from: %s to: %s in las 2 weeks before: %s', src, dst,
                           TimestampToStr('%Y-%m-%d %H:%M',gr[src][dst]['last_seen']))

        if len(gr[src][dst]['time']) >= (TWO_WEEK_AGGREGATION_PERIODS_COUNT):
            if len(gr[src][dst]['hwt_edge']) > 0 and gr[src][dst]['permanent_edge'] == True:
                actual_prediction_count = gr[src][dst]['prediction_count']
                if abs(gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][actual_prediction_count]) > hwt_flow_deviation:
                    print "kontrola ", abs(
                        gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][actual_prediction_count]), hwt_flow_deviation
                    gr[src][dst]['detection_seq'] += 1
                    gr[src][dst]['prediction_sum'] += gr[src][dst]['hwt_edge'][actual_prediction_count]
                    gr[src][dst]['values_lasts'].append(int(gr[src][dst]['time'][-1]))
                    if gr[src][dst]['detection_seq'] == num_blocks_report:
                        logger.warning('Edge %s - %s flows count: %s prediction: %s, %s minutes before %s', src, dst,
                                       int(sum(gr[src][dst]['values_lasts']) / num_blocks_report),
                                       int(gr[src][dst]['prediction_sum'] / num_blocks_report), num_blocks_report * 5,
                                       TimestampToStr('%Y-%m-%d %H:%M',gr[src][dst]['last_seen']))
                        gr[src][dst]['detection_seq'] = 0
                        gr[src][dst]['prediction_sum'] = 0
                        gr[src][dst]['values_lasts'] = deque()

                    gr[src][dst]['time'][-1] = gr[src][dst]['hwt_edge'][actual_prediction_count]
                else:
                    gr[src][dst]['detection_seq'] = 0
                    gr[src][dst]['prediction_sum'] = 0
                    gr[src][dst]['values_lasts'] = deque()
                gr[src][dst]['prediction_count'] += 1
                gr[src][dst]['hwt_a'].pop()
                gr[src][dst]['hwt_s'].pop()
                gr[src][dst]['hwt_s2'].pop()
                gr[src][dst]['hwt_edge'], gr[src][dst]['hwt_a'],gr[src][dst]['hwt_s'],gr[src][dst]['hwt_s2'] = hwt.HWTStep(gr[src][dst]['hwt_edge_last'][-1],gr[src][dst]['hwt_a'],gr[src][dst]['hwt_s'],gr[src][dst]['hwt_s2'],gr[src][dst]['hwt_params'][0],gr[src][dst]['hwt_params'][1], gr[src][dst]['hwt_params'][2],DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT,)
            if gr[src][dst]['prediction_count'] >= PREDICTION_INTERVALS:
                gr[src][dst]['hwt_edge_last'] = gr[src][dst]['hwt_edge']
                gr[src][dst]['hwt_edge'] = deque()
                gr[src][dst]['prediction_count'] = 0
                if gr[src][dst]['permanent_edge'] == True:
                    if gr[src][dst]['hwt_params'][0] is None or gr[src][dst]['hwt_params'][1]is None or gr[src][dst]['hwt_params'][2] is None:
                        gr[src][dst]['hwt_edge'],gr[src][dst]['hwt_params'],_,gr[src][dst]['hwt_a'],gr[src][dst]['hwt_s'],gr[src][dst]['hwt_s2'],gr[src][dst]['hwt_Y'] = hwt.HWT(list(gr[src][dst]['time']), DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT, PREDICTION_INTERVALS,
                                                                            alpha=gr[src][dst]['hwt_params'][0], gamma=gr[src][dst]['hwt_params'][1], delta=gr[src][dst]['hwt_params'][2],
                                                                            initial_values_optimization=[0.1, 0.2, 0.2])
                        gr[src][dst]['hwt_edge_last'] = gr[src][dst]['hwt_edge']


                    else:

                        gr[src][dst]['gr[src][dst]'], gr[src][dst]['hwt_a'],gr[src][dst]['hwt_s'],gr[src][dst]['hwt_s2'] = hwt.HWTStep(gr[src][dst]['time'][-1],gr[src][dst]['hwt_a'],gr[src][dst]['hwt_s'],gr[src][dst]['hwt_s2'],gr[src][dst]['hwt_params'][0],gr[src][dst]['hwt_params'][1], gr[src][dst]['hwt_params'][2],DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT,)




def NodeAnalysis(gr, hwt_flow_deviation, num_blocks_report):
    for node_id in gr.nodes():
        if gr.node[node_id]['time'][-1] == 0:
            if gr.node[node_id]['time'][-2] != 0 and gr.node[node_id]['permanent_addr'] == False:
                logger.debug('IP address: %s disconnected in time: %s', node_id,
                             TimestampToStr('%Y-%m-%d %H:%M',gr.node[node_id]['last_seen']))
            elif gr.node[node_id]['permanent_addr']:
                gr.node[node_id]['permanent_addr'] = False
                logger.warning('Permanent address: %s disconnected in time: %s - %s', node_id,
                               TimestampToStr('%Y-%m-%d %H:%M',gr.node[node_id]['last_seen'] - 300),
                               TimestampToStr('%Y-%m-%d %H:%M',gr.node[node_id]['last_seen']))
        elif gr.node[node_id]['time'][-2] == 0:
            logger.debug('IP address: %s connected in time: %s', node_id,
                         TimestampToStr('%Y-%m-%d %H:%M', gr.node[node_id]['last_seen']))

        if not 0 in gr.node[node_id]['time'] and gr.node[node_id]['permanent_addr'] == False:
            gr.node[node_id]['permanent_addr'] = True
            gr.node[node_id]['prediction_count'] = PREDICTION_INTERVALS
            gr.node[node_id]['hwt_addr'] = deque()
            logger.warning('New permanent address: %s in last 2 weeks before:%s', node_id,
                           TimestampToStr('%Y-%m-%d %H:%M',gr.node[node_id]['last_seen']))

        if len(gr.node[node_id]['time']) >= (TWO_WEEK_AGGREGATION_PERIODS_COUNT):
            if len(gr.node[node_id]['hwt_addr']) > 0 and gr.node[node_id]['permanent_addr'] == True:
                actual_prediction_count = gr.node[node_id]['prediction_count']
                if abs(gr.node[node_id]['time'][-1] - gr.node[node_id]['hwt_addr'][actual_prediction_count]) > hwt_flow_deviation:
                    gr.node[node_id]['detection_seq'] += 1
                    gr.node[node_id]['prediction_sum'] += gr.node[node_id]['hwt_addr'][actual_prediction_count]
                    gr.node[node_id]['values_lasts'].append(int(gr.node[node_id]['time'][-1]))
                    if gr.node[node_id]['detection_seq'] == num_blocks_report:
                        logger.warning(
                            'IP %s flows count:%s prediction:%s per 5 miutes during last %s minutes before %s', node_id,
                            int(sum(gr.node[node_id]['values_lasts']) / num_blocks_report),
                            int(gr.node[node_id]['prediction_sum'] / num_blocks_report), num_blocks_report * 5,
                            TimestampToStr('%Y-%m-%d %H:%M',gr.node[node_id]['last_seen']))
                        gr.node[node_id]['detection_seq'] = 0
                        gr.node[node_id]['prediction_sum'] = 0
                        gr.node[node_id]['values_lasts'] = deque()
                    gr.node[node_id]['time'][-1] = gr.node[node_id]['hwt_addr'][actual_prediction_count]
                else:
                    gr.node[node_id]['detection_seq'] = 0
                    gr.node[node_id]['prediction_sum'] = 0
                    gr.node[node_id]['values_lasts'] = deque()
                gr.node[node_id]['hwt_a'].pop()
                gr.node[node_id]['hwt_s'].pop()
                gr.node[node_id]['hwt_s2'].pop()
                gr.node[node_id]['prediction_count'] += 1
                gr.node[node_id]['hwt_addr'], gr.node[node_id]['hwt_a'],gr.node[node_id]['hwt_s'],gr.node[node_id]['hwt_s2'] = hwt.HWTStep(gr.node[node_id]['hwt_addr_last'][-1],gr.node[node_id]['hwt_a'],gr.node[node_id]['hwt_s'],gr.node[node_id]['hwt_s2'],gr.node[node_id]['hwt_params'][0],gr.node[node_id]['hwt_params'][1], gr.node[node_id]['hwt_params'][2],DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT,)
            if gr.node[node_id]['prediction_count'] >= PREDICTION_INTERVALS:
                gr.node[node_id]['hwt_addr_last'] = gr.node[node_id]['hwt_addr']
                gr.node[node_id]['hwt_addr'] = deque()
                gr.node[node_id]['prediction_count'] = 0
                if gr.node[node_id]['permanent_addr'] == True:
                    if gr.node[node_id]['hwt_params'][0] is None or gr.node[node_id]['hwt_params'][1]is None or gr.node[node_id]['hwt_params'][2] is None:
                        gr.node[node_id]['hwt_addr'],gr.node[node_id]['hwt_params'],_,gr.node[node_id]['hwt_a'],gr.node[node_id]['hwt_s'],gr.node[node_id]['hwt_s2'],gr.node[node_id]['hwt_Y'] = hwt.HWT(list(gr.node[node_id]['time']), DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT, PREDICTION_INTERVALS,
                                                                            alpha=gr.node[node_id]['hwt_params'][0], gamma=gr.node[node_id]['hwt_params'][1], delta=gr.node[node_id]['hwt_params'][2],
                                                                            initial_values_optimization=[0.1, 0.2, 0.2])
                        gr.node[node_id]['hwt_addr_last'] = gr.node[node_id]['hwt_addr']


                    else:
                        gr.node[node_id]['hwt_addr'], gr.node[node_id]['hwt_a'],gr.node[node_id]['hwt_s'],gr.node[node_id]['hwt_s2'] = hwt.HWTStep(gr.node[node_id]['time'][-1],gr.node[node_id]['hwt_a'],gr.node[node_id]['hwt_s'],gr.node[node_id]['hwt_s2'],gr.node[node_id]['hwt_params'][0],gr.node[node_id]['hwt_params'][1], gr.node[node_id]['hwt_params'][2],DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT,)



def FlowAnalysis(gr, hwt_flow_deviation, num_blocks_report, flow_prediction_list, measured_data_list,
                 flow_prediction_list_total, measured_data_list_total):
    if len(gr.graph['flow_count']) >= TWO_WEEK_AGGREGATION_PERIODS_COUNT:
        if len(gr.graph['hwt_flow']) > 0:
            actual_prediction_count = gr.graph['prediction_count']
            flow_prediction_list.append(gr.graph['hwt_flow'][actual_prediction_count])
            measured_data_list.append(gr.graph['flow_count'][-1])
            flow_prediction_list_total.append(gr.graph['hwt_flow'][actual_prediction_count])
            measured_data_list_total.append(gr.graph['flow_count'][-1])

            if abs(gr.graph['flow_count'][-1] - gr.graph['hwt_flow'][actual_prediction_count]) > hwt_flow_deviation:
                gr.graph['detection_seq'] += 1
                gr.graph['prediction_sum'] += gr.graph['hwt_flow'][actual_prediction_count]
                gr.graph['values_lasts'].append(int(gr.graph['flow_count'][-1]))
                print len(gr.graph['values_lasts'])
                if gr.graph['detection_seq'] == num_blocks_report:
                    logger.warning(
                        'Average flow count: %s, average prediction count: %s per 5 miutes during last %s minutes before %s',
                        int(sum(gr.graph['values_lasts']) / num_blocks_report),
                        int(gr.graph['prediction_sum'] / num_blocks_report), num_blocks_report * 5,
                        TimestampToStr('%Y-%m-%d %H:%M',gr.graph['last_flow']))
                    gr.graph['detection_seq'] = 0
                    gr.graph['prediction_sum'] = 0
                    gr.graph['values_lasts'] = deque()
                gr.graph['hwt_a'].pop()
                gr.graph['hwt_s'].pop()
                gr.graph['hwt_s2'].pop()

                #print len(gr.graph['hwt_flow']),len(gr.graph['hwt_a']),len(gr.graph['hwt_flow_last'])
                gr.graph['hwt_flow'], gr.graph['hwt_a'],gr.graph['hwt_s'],gr.graph['hwt_s2'] = hwt.HWTStep(gr.graph['hwt_flow_last'][-1],gr.graph['hwt_a'],gr.graph['hwt_s'],gr.graph['hwt_s2'],gr.graph['hwt_params'][0],gr.graph['hwt_params'][1], gr.graph['hwt_params'][2],DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT,)
            else:
                gr.graph['detection_seq'] = 0
                gr.graph['prediction_sum'] = 0
                gr.graph['values_lasts'] = deque()
            gr.graph['prediction_count'] += 1

        if gr.graph['prediction_count'] >= PREDICTION_INTERVALS:
            gr.graph['hwt_flow_last'] = gr.graph['hwt_flow']
            gr.graph['hwt_flow'] = deque()
            gr.graph['prediction_count'] = 0
            if 0 not in gr.graph['flow_count']:
                if gr.graph['hwt_params'][0] is None or gr.graph['hwt_params'][1]is None or gr.graph['hwt_params'][2] is None:
                    gr.graph['hwt_flow'],gr.graph['hwt_params'],_,gr.graph['hwt_a'],gr.graph['hwt_s'],gr.graph['hwt_s2'],gr.graph['hwt_Y'] = hwt.HWT(list(gr.graph['flow_count']), DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT, PREDICTION_INTERVALS,
                                                                        alpha=gr.graph['hwt_params'][0], gamma=gr.graph['hwt_params'][1], delta=gr.graph['hwt_params'][2],
                                                                        initial_values_optimization=[0.1, 0.2, 0.2])
                    gr.graph['hwt_flow_last'] = gr.graph['hwt_flow']



                else:

                    gr.graph['hwt_flow'], gr.graph['hwt_a'],gr.graph['hwt_s'],gr.graph['hwt_s2'] = hwt.HWTStep(gr.graph['flow_count'][-1],gr.graph['hwt_a'],gr.graph['hwt_s'],gr.graph['hwt_s2'],gr.graph['hwt_params'][0],gr.graph['hwt_params'][1], gr.graph['hwt_params'][2],DAY_PERIODS_COUNT, WEEK_AGGREGATION_PERIODS_COUNT,)



def QuietPeriodProcess(gr,threshold):
    if gr.graph['flow_count'][-2] > threshold and gr.graph['flow_count'][-1] < threshold:
        logger.warning('Low traffic period started with %s flows per five minutes',gr.graph['flow_count'][-1])
    elif gr.graph['flow_count'][-2] < threshold and gr.graph['flow_count'][-1] > threshold:
        logger.warning('High traffic period started with %s flows per five minutes',gr.graph['flow_count'][-1])





def StrToDatetime(time_str, time_format):
    return datetime.datetime.strptime(time_str, time_format)

def TimestampToStr(time_format,timestamp):
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

def FillGraph (gr,rec,is_learning, next_period,stats_trigger,rec_buffer,directory):
    if next_period:
        stats_trigger += TIME_WINDOW_SECONDS
        for record in rec_buffer:
            gr = AddRecord(record, gr, prop_array, ip_range, next_period, is_learning)
            next_period = False
        if len(gr.graph['flow_count']) >= TWO_WEEK_AGGREGATION_PERIODS_COUNT and is_learning == True:
            is_learning = False
            ExportData(directory)
        rec_buffer = []
        rec_buffer.append(rec)
    elif rec.TIME_LAST.getSec() > stats_trigger - TIME_WINDOW_SECONDS:
        rec_buffer.append(rec)
    elif rec.TIME_LAST.getSec() <= stats_trigger - TIME_WINDOW_SECONDS:
        gr = AddRecord(rec, gr, prop_array, ip_range, next_period,  is_learning)
        next_period = False
    return gr, is_learning, next_period,stats_trigger,rec_buffer


def FillGraphRecord(gr, rec,next_period):
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
            logger.warning('New connection from: %s to: %s in time: %s', src_ip, dst_ip,TimestampToStr('%Y-%m-%d %H:%M',rec.TIME_LAST.getSec()))
        gr.add_edge(src_ip, dst_ip, permanent_edge=False, detection_seq=0,
                    prediction_count=PREDICTION_INTERVALS, hwt_edge=deque(),hwt_edge_last=deque(), hwt_params = [None,None,None], values_lasts=deque(), prediction_sum=0,
                    prediction_eval=0, last_seen=rec.TIME_LAST.getSec(), time=deque(),hwt_a = deque(),hwt_s = deque(),hwt_s2 = deque(),hwt_Y =[])
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
            print "new ip ", ip
            logger.warning('New IP address: %s in time: %s', ip,
                           TimestampToStr('%Y-%m-%d %H:%M',rec.TIME_LAST.getSec()))
        gr.add_node(ip, permanent_addr=False, detection_seq=0, prediction_count=PREDICTION_INTERVALS,
                    hwt_addr=deque(),hwt_addr_last=deque(),hwt_params = [None,None,None], values_lasts=deque(), prediction_sum=0, prediction_eval=0,
                    last_seen=rec.TIME_LAST.getSec(), time=deque(),hwt_a = deque(),hwt_s = deque(),hwt_s2 = deque(),hwt_Y =[])
        while len(gr.node[ip]['time']) < len(gr.graph['flow_count']) - 1:
            gr.node[ip]['time'].append(0)
        gr.node[ip]['time'].append(1)

    return gr

def NextPeriodProcess(gr, next_period):
    if next_period:
        if len(gr.graph['flow_count']) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:
            gr.graph['flow_count'].popleft()
        if len(gr.graph['hwt_flow']) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:
            gr.graph['hwt_flow'].popleft()
        if len(gr.graph['hwt_flow_last']) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:
            gr.graph['hwt_flow_last'].popleft()
        print "len awt a", len(gr.graph['hwt_a'])
        if len(gr.graph['hwt_a']) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:
            gr.graph['hwt_a'].popleft()
        if len(gr.graph['hwt_s']) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:
            gr.graph['hwt_s'].popleft()
        if len(gr.graph['hwt_s2']) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:
            gr.graph['hwt_s2'].popleft()
        for node_id in gr.nodes():
            gr.node[node_id]['time'].append(0)
            if len(gr.node[node_id]['time']) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:
                gr.node[node_id]['time'].popleft()
        for src, dst in gr.edges():
            gr[src][dst]['time'].append(0)
            if len(gr[src][dst]['time']) > TWO_WEEK_AGGREGATION_PERIODS_COUNT:
                gr[src][dst]['time'].popleft()

    return gr


def AddRecord(rec, gr, properties, ip_range, next_period,  is_learning):
    src_ip = CheckIPRange(str(rec.SRC_IP), ip_range)
    dst_ip = CheckIPRange(str(rec.DST_IP), ip_range)
    gr = FillGraphRecord(gr,rec,next_period)
    gr = NextPeriodProcess(gr,next_period)
    gr = FillNodeRecord(next_period, src_ip, rec, gr, is_learning)
    gr = FillNodeRecord(next_period, dst_ip, rec, gr, is_learning)
    gr = FillEdgeRecord(next_period, src_ip, dst_ip, rec, gr, properties, is_learning)
    return gr


def ParseAdditionalParams(parser, prop_array):
    options, args = parser.parse_args()

    properties = options.properties
    ip_range = options.ip_range
    if properties is not None:
        prop_array = properties.split(',')

    if ip_range is not None:
        ip_range = ip_range.split('-')
        ip_range = list(ipaddress.summarize_address_range(ipaddress.ip_address(unicode(ip_range[0], "utf-8")),
                                                          ipaddress.ip_address(unicode(ip_range[1], "utf-8"))))

    return prop_array, ip_range, options.directory, options.learning


def ExportData(directory="data"):
    print "Exporting data"
    gr_to_save = nx.DiGraph(gr)
    gr_to_save.graph['flow_count'] = list(gr_to_save.graph['flow_count'])
    gr_to_save.graph['values_lasts'] = list(gr_to_save.graph['values_lasts'])
    gr_to_save.graph['hwt_params'] = [None,None,None]
    gr_to_save.graph['hwt_a'] = []
    gr_to_save.graph['hwt_s'] = []
    gr_to_save.graph['hwt_s2'] = []
    gr_to_save.graph['hwt_Y'] =[]
    for node_id, node_attrs in gr_to_save.nodes(data=True):
        gr_to_save.node[node_id]['permanent_addr'] = True
        for tm in gr_to_save.node[node_id]['time']:
            if tm == 0:
                gr_to_save.node[node_id]['permanent_addr'] = False
                break
        gr_to_save.node[node_id]['time'] = list(node_attrs['time'])
        gr_to_save.node[node_id]['hwt_addr'] = list()
        gr_to_save.node[node_id]['hwt_addr_last'] = list()
        gr_to_save.node[node_id]['values_lasts'] = list()
        gr_to_save.node[node_id]['hwt_params'] = [None,None,None]
        gr_to_save.node[node_id]['hwt_a'] = []
        gr_to_save.node[node_id]['hwt_s'] = []
        gr_to_save.node[node_id]['hwt_s2'] = []
        gr_to_save.node[node_id]['hwt_Y'] =[]
    for src, dst, edge_attrs in gr_to_save.edges(data=True):
        gr_to_save[src][dst]['permanent_edge'] = True
        for tm in gr_to_save[src][dst]['time']:
            if tm == 0:
                gr_to_save[src][dst]['permanent_edge'] = False
                break
        gr_to_save[src][dst]['time'] = list(edge_attrs['time'])
        gr_to_save[src][dst]['hwt_edge'] = list()
        gr_to_save[src][dst]['hwt_edge_last'] = list()
        gr_to_save[src][dst]['values_lasts'] = list()
        gr_to_save[src][dst]['hwt_params'] = [None,None,None]
        gr_to_save[src][dst]['hwt_a'] = []
        gr_to_save[src][dst]['hwt_s'] = []
        gr_to_save[src][dst]['hwt_s2'] = []
        gr_to_save[src][dst]['hwt_Y'] =[]
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
        filehandle = open(str(directory) + "/learned.json", 'w')
    except IOError:
        print "Can not write data."
        return
    filehandle.write(json.dumps(json_graph.node_link_data(gr_to_save), sort_keys=True, indent=2, separators=(',', ': ')))


def ImportData(rec, directory="data"):
    print "Importing data"
    print directory
    if not os.path.exists(directory):
        print "Could not find learned data, start with -l parameter first."
        return
    try:
        filehandle = open(str(directory) + "/learned.json", 'r')
    except:
        print "Could not find learned data, start with -l parameter first.."
        return

    data = json.loads(filehandle.read())
    graph = json_graph.node_link_graph(data, directed=True, multigraph=False,
                                       attrs={'id': 'id', 'source': 'source', 'target': 'target',
                                              'last_seen': 'last_seen', 'time': 'time'})
    # print graph['254.158.184.235']['106.53.240.142']['time']
    for src, dst, edge_attrs in graph.edges(data=True):
        graph[src][dst]['permanent_edge'] = True
        graph[src][dst]['time'] = deque(edge_attrs['time'])
        graph[src][dst]['values_lasts'] = deque(edge_attrs['values_lasts'])
        graph[src][dst]['hwt_edge'] = deque()
        graph[src][dst]['hwt_edge_last'] = deque()
        for tm in graph[src][dst]['time']:
            if tm == 0:
                graph[src][dst]['permanent_edge'] = False
                break

    for node_id, node_attrs in graph.nodes(data=True):
        graph.node[node_id]['time'] = deque(node_attrs['time'])
        graph.node[node_id]['permanent_addr'] = True
        graph.node[node_id]['values_lasts'] = deque(node_attrs['values_lasts'])
        graph.node[node_id]['hwt_addr'] = deque()
        graph.node[node_id]['hwt_addr_last'] = deque()
        graph.node[node_id]['hwt_a'] = deque()
        graph.node[node_id]['hwt_s'] = deque()
        graph.node[node_id]['hwt_s2'] = deque()
        graph.node[node_id]['hwt_Y'] = deque()
        for tm in graph.node[node_id]['time']:
            if tm == 0:
                graph.node[node_id]['permanent_addr'] = False
                break

    graph.graph['hwt_a'] = deque()
    graph.graph['hwt_s'] = deque()
    graph.graph['hwt_s2'] = deque()
    graph.graph['hwt_Y'] = deque()
    graph.graph['hwt_flow'] = deque()
    graph.graph['hwt_flow_last'] = deque()
    graph.graph['values_lasts'] = deque()

    #print graph.graph['last_flow'], rec.TIME_LAST.getSec()
    loaded_interval_index = (graph.graph['last_flow'] / (TIME_WINDOW_SECONDS)) % (WEEK_AGGREGATION_PERIODS_COUNT)
    actual_interval_index = (rec.TIME_LAST.getSec() / (TIME_WINDOW_SECONDS)) % (WEEK_AGGREGATION_PERIODS_COUNT)
    time_shift  = loaded_interval_index - actual_interval_index
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

# Initialize module
ifc_spec = trap.parseParams(sys.argv, module_info)

trap.init(module_info, ifc_spec)

trap.registerDefaultSignalHandler()  # This is needed to allow module termination using s SIGINT or SIGTERM signal

# this module accepts all UniRec fieds -> set required format:
trap.set_required_fmt(0, trap.TRAP_FMT_UNIREC, "")

# Specifier of UniRec records will be received during libtrap negotiation


prop_array, ip_range, directory, is_learning = ParseAdditionalParams(parser, prop_array)

gr = FlowProcess(is_learning, gr, prop_array, ip_range)

print is_learning

