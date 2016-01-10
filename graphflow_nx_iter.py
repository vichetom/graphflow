#!/usr/bin/python

import pdb
import sys
import os.path
import traceback
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "..","python","/home/tom/nemea/nemea-install/share/nemea-python","/home/tom/nemea/nemea-install/","/home/tom/nemea/nemea-install/lib", "/home/tom/nemea/nemea/nemea-framework/python"))
import trap
import unirec
#from py2neo import Graph, Node, Relationship,authenticate
import networkx as nx
#import graph_tool.all as grt
from datetime import datetime
import time
import datetime
import  ipaddress
import json
from networkx.readwrite import json_graph
import logging
from math import ceil
from collections import deque
import hwt 
import matplotlib.pyplot as plt

gr=nx.DiGraph(flow_count=deque(),last_flow=0,)
rec_buffer = []
time_window = 5 * 60
time_stats_window = 0
stats_interval = 0
newest_time = 0
src_ip = None
dst_ip = None
rec_time = None
properties = None
prop_array = None
option_dict = None
ip_range = None
allowed_properties = ["PORT","BYTES", "PACKETS", "DST_PORT", "SRC_PORT", "HTTP_RSP_CODE", "PROTOCOL", "TCP_FLAGS", "TTL", "TIME_FIRST", "TIME_LAST"]
incounter = 0
is_learning = False
minute_accuracy = 3
week_seconds = 604800
number_of_periods = 1
flow_count_deviation = 50
prediction_intervals = 0

logger = logging.getLogger(__name__)
handler = logging.FileHandler('graphflow.log'+str(datetime.datetime.now()))
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

# How to add options of module
from optparse import OptionParser
parser = OptionParser(add_help_option=False)
parser.add_option("-l", "--learning",
          action="store_true",dest="learning",default=False,
         help="Turns learning phase on and off. Choose True/False")
parser.add_option("-p", "--properties",
         dest="properties",default=None,
         help="Set properties to be saved. Separated by comma. Its possible to choose from: "+str(allowed_properties))
parser.add_option("-r", "--ip-range",
         dest="ip_range",default=None,
         help="Set range of ip addresses in local network first ip-last ip ")
parser.add_option("-e", "--export-interval",
         dest="export_interval",default=60,
         help="Set data export interval. Default is 60 sec.")
parser.add_option("-d", "--directory", dest="directory",
         help="Set directory to save data. If parameter is not set, data are not saved.", metavar="FILE")
parser.add_option("-q", "--quiet",
         action="store_false", dest="verbose", default=True,
         help="don't print status messages to stdout")

#------------------------------------------------------


def FlowProcess(UR_Flow, is_learning, gr, prop_array, ip_range):
   global prediction_intervals

   saved = False
   stats_trigger = 0
   rec_buffer = []
   prediction_intervals = prediction_count  = 12*24
   incounter = 0
   next_period = False
   time_last_seen = 0
   first_timestamp = 0
   detection_seq = 0
   num_blocks_report = 12
   perm_addresses = []
   hwt_flow_deviation = 0
   flow_prediction_list = [0]
   flow_prediction_list_total = [0]
   measured_data_list = [0]
   measured_data_list_total = [0]
   plot_smooth_step = 12
   plot_interval = 0
   plot_smooth_interval = 0
 
   #print rec.TIME_LAST.getSec(), stats_trigger  
   
   
   

   # Main loop (trap.stop is set to True when SIGINT or SIGTERM is received)
   while not trap.stop:
      # Read data from input interface
      try:
         data = trap.recv(0)
      except trap.EFMTMismatch:
         print("Error: output and input interfaces data format or data specifier mismatch")
         break
      except trap.EFMTChanged as e:
            # Get data format from negotiation
         (fmttype, fmtspec) = trap.get_data_fmt(trap.IFC_INPUT, 0)
         UR_Flow = unirec.CreateTemplate("UR_Flow", fmtspec)
         print("Negotiation:", fmttype, fmtspec)
         print "Negotiation"
         # Set the same format for output IFC negotiation
         #trap.set_data_fmt(0, fmttype, fmtspec)
         data = e.data
      except trap.ETerminated:
         print "fmt exception"
         break

      # Check for "end-of-stream" record
      if len(data) <= 1:
         break

   
      rec = UR_Flow(data)
      if is_learning == False and incounter == 0:
         gr = ReadLearnedData(rec,)
         gr.graph['prediction_count'] = prediction_intervals
         for node_id in gr.nodes():
            gr.node[node_id]['prediction_count'] = prediction_intervals
         for src,dst in gr.edges():
            gr[src][dst]['prediction_count'] = prediction_intervals
         
         #if is_learning == False:
            #for node,node_attrs in gr.nodes(data=True):
               #print node,node_attrs['permanent_addr']
            #for src,dst,edge_attrs in gr.edges(data=True):
               #print src,dst,edge_attrs['permanent_edge']
         #flow_quiet_period_limit = QuietPeriodProcess(gr)
         #print flow_quiet_period_limit

        
      #print "test",gr.graph['prediction_count']
      if incounter == 0:
         first_timestamp = rec.TIME_LAST.getSec()
         stats_trigger = rec.TIME_LAST.getSec() - (rec.TIME_LAST.getSec()%60)  + (10*60)
         hwt_flow_deviation = 200
         print "hwt deviation", hwt_flow_deviation

      time_last_seen = rec.TIME_LAST.getSec()
      incounter+=1  



      if rec.TIME_LAST.getSec() > stats_trigger:
         next_period = True
      if is_learning == False and next_period == True:
         plot_interval += 1
         plot_smooth_interval +=1
         FlowAnalysis(gr,hwt_flow_deviation,num_blocks_report,flow_prediction_list,measured_data_list,flow_prediction_list_total,measured_data_list_total)
         NodeAnalysis(gr,hwt_flow_deviation,num_blocks_report)
         EdgeAnalysis(gr,hwt_flow_deviation,num_blocks_report)


      if is_learning == False:
         if plot_smooth_interval == plot_smooth_step:
            print "adding step"
            plot_smooth_interval = 0
            flow_prediction_list.append(0)
            measured_data_list.append(0)
            flow_prediction_list_total.append(0)
            measured_data_list_total.append(0)
            

         #print time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr.graph['last_flow'])) 
         if plot_interval == 12*24*7 and plot_interval > plot_smooth_step:
            print flow_prediction_list,measured_data_list
            PlotFlow(flow_prediction_list,measured_data_list,incounter)
            plot_interval = 0
            flow_prediction_list = [0]
            measured_data_list = [0]
            plt.clf()
         
         
      if next_period == True:
         stats_trigger += time_window
         for record in rec_buffer:
            gr = AddRecord(record, gr, prop_array, ip_range,next_period,first_timestamp,is_learning) 
            next_period = False
         if len(gr.graph['flow_count']) >= (24*12*7*2)  and is_learning == True:
            is_learning = False
            ExportData(directory)
         rec_buffer = []
         rec_buffer.append(rec)
      elif rec.TIME_LAST.getSec() > stats_trigger - time_window:
         rec_buffer.append(rec)
      elif rec.TIME_LAST.getSec() <= stats_trigger - time_window:
         gr = AddRecord(rec, gr, prop_array, ip_range,next_period,first_timestamp,is_learning)
         next_period = False
   for record in rec_buffer:
      gr = AddRecord(record, gr, prop_array, ip_range,next_period,first_timestamp,is_learning)
      next_period = False
   if len(gr.graph['flow_count']) == (24*12*7*2)  and is_learning ==  True:
      is_learning = False
      ExportData(directory)
   print len(gr.graph['flow_count']), (24*12*7*2),  gr.nodes(), next_period,gr.graph['last_flow']
   PlotFlow(flow_prediction_list_total,measured_data_list_total,incounter)
   return gr, first_timestamp,time_last_seen

def PlotFlow(flow_prediction_list,measured_data_list,incounter):
   plt.figure(figsize=(20,15))
   print flow_prediction_list,measured_data_list
   plt.plot(flow_prediction_list,label='prediction data')
   plt.plot(measured_data_list,label='real data')
   plt.legend()
   plt.savefig(str(incounter)+'prediction.png')
   plt.clf()
   print "plotting deleting"



def EdgeAnalysis(gr,hwt_flow_deviation,num_blocks_report):
    for src,dst in gr.edges():
      if gr[src][dst]['time'][-1] == 0:  
         if gr[src][dst]['time'][-2] != 0 and gr[src][dst]['permanent_edge'] == False:
            logger.debug('Connection from: %s to: %s disconnected in time: %s', src,dst, time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr[src][dst]['last_seen'])))
         elif gr[src][dst]['permanent_edge'] == True:
            gr[src][dst]['permanent_edge'] = False
            #print gr.node[src]['permanent_addr'],gr.node[dst]['permanent_addr']
            logger.warning('Permanent connection from: %s to: %s disconnected in time: %s - %s', src,dst, time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr[src][dst]['last_seen']-300)),time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr[src][dst]['last_seen'])))
      elif gr[src][dst]['time'][-2] == 0:
         logger.debug('Connection from: %s to: %s connected in time: %s', src,dst, time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr[src][dst]['last_seen'])))
      if not 0 in gr[src][dst]['time'] and gr[src][dst]['permanent_edge'] == False:
         gr[src][dst]['permanent_edge'] = True
         gr[src][dst]['prediction_count'] = prediction_intervals
         gr[src][dst]['hwt_edge'] = deque()
         logger.warning('New permanent connection from: %s to: %s in las 2 weeks before: %s', src,dst, time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr[src][dst]['last_seen'])))

      if len(gr[src][dst]['time']) >= (24*12*7*2):
         if len(gr[src][dst]['hwt_edge']) > 0 and gr[src][dst]['permanent_edge'] == True:
            prediction_count = gr[src][dst]['prediction_count']
            #print "Edge prediction:",src,dst,gr[src][dst]['hwt_edge'][0][prediction_count], gr[src][dst]['time'][-1]
            #if gr[src][dst]['time'][-1] > gr[src][dst]['hwt_edge'][0][prediction_count] + (gr[src][dst]['hwt_edge'][0][prediction_count] * flow_count_deviation) or gr[src][dst]['time'][-1] < gr[src][dst]['hwt_edge'][0][prediction_count] - (gr[src][dst]['hwt_edge'][0][prediction_count] * flow_count_deviation):
            if abs(gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][0][prediction_count]) > hwt_flow_deviation:
               print "kontrola ", abs(gr[src][dst]['time'][-1] - gr[src][dst]['hwt_edge'][0][prediction_count]), hwt_flow_deviation
               gr[src][dst]['detection_seq'] += 1
               gr[src][dst]['prediction_sum'] += gr[src][dst]['hwt_edge'][0][prediction_count]
               gr[src][dst]['values_lasts'].append(int(gr[src][dst]['time'][-1]))
               if gr[src][dst]['detection_seq'] == num_blocks_report:
                  logger.warning('Edge %s - %s flows count: %s prediction: %s, %s minutes before %s', src,dst,int(sum(gr[src][dst]['values_lasts'])/num_blocks_report),int(gr[src][dst]['prediction_sum']/num_blocks_report),num_blocks_report*5,time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr[src][dst]['last_seen'])))
                  gr[src][dst]['detection_seq'] = 0
                  gr[src][dst]['prediction_sum'] = 0
                  gr[src][dst]['values_lasts'] = deque()

               gr[src][dst]['time'][-1] = gr[src][dst]['hwt_edge'][0][prediction_count]
            else:
               gr[src][dst]['detection_seq'] = 0
               gr[src][dst]['prediction_sum'] = 0
               gr[src][dst]['values_lasts'] = deque()
            gr[src][dst]['prediction_count'] += 1

      if gr[src][dst]['prediction_count'] >= prediction_intervals:
         gr[src][dst]['hwt_edge'] = deque()
         gr[src][dst]['prediction_count'] = 0
         if gr[src][dst]['permanent_edge'] == True: 
            gr[src][dst]['hwt_edge'] = hwt.HWT(list(gr[src][dst]['time']), 24*12, 24*12*7, prediction_intervals, alpha = None,  gamma = None,delta=None, initial_values_optimization=[0.1, 0.2, 0.2])



def NodeAnalysis(gr,hwt_flow_deviation,num_blocks_report):
   for node_id in gr.nodes():
      if gr.node[node_id]['time'][-1] == 0:
         if gr.node[node_id]['time'][-2] != 0 and gr.node[node_id]['permanent_addr'] == False:
            logger.debug('IP address: %s disconnected in time: %s', node_id, time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr.node[node_id]['last_seen'])))
         elif gr.node[node_id]['permanent_addr'] == True:
            gr.node[node_id]['permanent_addr'] = False
            logger.warning('Permanent address: %s disconnected in time: %s - %s', node_id, time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr.node[node_id]['last_seen']-300)),time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr.node[node_id]['last_seen'])))
      elif gr.node[node_id]['time'][-2] == 0:
         logger.debug('IP address: %s connected in time: %s', node_id, time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr.node[node_id]['last_seen'])))

      if not 0 in gr.node[node_id]['time'] and gr.node[node_id]['permanent_addr'] == False:
         gr.node[node_id]['permanent_addr'] = True
         gr.node[node_id]['prediction_count'] = prediction_intervals
         gr.node[node_id]['hwt_addr'] = deque()
         logger.warning('New permanent address: %s in last 2 weeks before:%s', node_id, time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr.node[node_id]['last_seen'])))
      
      if len(gr.node[node_id]['time']) >= (24*12*7*2):
         if len(gr.node[node_id]['hwt_addr']) > 0 and gr.node[node_id]['permanent_addr'] == True:
            prediction_count = gr.node[node_id]['prediction_count']
            #print "Addr prediction:",node_id,gr.node[node_id]['hwt_addr'][0][prediction_count], gr.node[node_id]['time'][-1]
            #if gr.node[node_id]['time'][-1] > gr.node[node_id]['hwt_addr'][0][prediction_count] + (gr.node[node_id]['hwt_addr'][0][prediction_count] * flow_count_deviation) or gr.node[node_id]['time'][-1] < gr.node[node_id]['hwt_addr'][0][prediction_count] - (gr.node[node_id]['hwt_addr'][0][prediction_count] * flow_count_deviation):
            if abs(gr.node[node_id]['time'][-1] - gr.node[node_id]['hwt_addr'][0][prediction_count]) > hwt_flow_deviation:
               gr.node[node_id]['detection_seq'] += 1
               gr.node[node_id]['prediction_sum'] += gr.node[node_id]['hwt_addr'][0][prediction_count] 
               gr.node[node_id]['values_lasts'].append(int(gr.node[node_id]['time'][-1]))
               if gr.node[node_id]['detection_seq'] == num_blocks_report:
                  logger.warning('IP %s flows count:%s prediction:%s per 5 miutes during last %s minutes before %s', node_id,int(sum(gr.node[node_id]['values_lasts'])/num_blocks_report),int(gr.node[node_id]['prediction_sum']/num_blocks_report),num_blocks_report*5,time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr.node[node_id]['last_seen'])))
                  gr.node[node_id]['detection_seq'] = 0
                  gr.node[node_id]['prediction_sum'] = 0
                  gr.node[node_id]['values_lasts'] = deque()
               gr.node[node_id]['time'][-1] = gr.node[node_id]['hwt_addr'][0][prediction_count]
            else:
               gr.node[node_id]['detection_seq'] = 0
               gr.node[node_id]['prediction_sum'] = 0
               gr.node[node_id]['values_lasts'] = deque()

            gr.node[node_id]['prediction_count'] += 1
      
         if gr.node[node_id]['prediction_count'] >= prediction_intervals:
            gr.node[node_id]['hwt_addr'] = deque()
            gr.node[node_id]['prediction_count'] = 0
            if gr.node[node_id]['permanent_addr'] == True: 
               gr.node[node_id]['hwt_addr'] = hwt.HWT(list(gr.node[node_id]['time']), 24*12, 24*12*7, prediction_intervals, alpha = None,  gamma = None,delta=None, initial_values_optimization=[0.1, 0.2, 0.2])



def FlowAnalysis(gr,hwt_flow_deviation, num_blocks_report,flow_prediction_list,measured_data_list,flow_prediction_list_total,measured_data_list_total):
   if len(gr.graph['flow_count']) >= 24*12*7*2:
      if len(gr.graph['hwt_flow']) > 0:
         prediction_count = gr.graph['prediction_count']
         #print gr.graph['hwt_flow'][0][prediction_count], gr.graph['flow_count'][-1],time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr.graph['last_flow'])) 
         #if (gr.graph['flow_count'][-1] > gr.graph['hwt_flow'][0][prediction_count] + (gr.graph['hwt_flow'][0][prediction_count] * flow_count_deviation) or gr.graph['flow_count'][-1] < gr.graph['hwt_flow'][0][prediction_count] - (gr.graph['hwt_flow'][0][prediction_count] * flow_count_deviation)) and not abs(gr.graph['flow_count'][-1] - gr.graph['hwt_flow'][0][prediction_count]) < gr.graph['hwt_flow'] :
         flow_prediction_list[-1]+=gr.graph['hwt_flow'][0][prediction_count]
         measured_data_list[-1]+=gr.graph['flow_count'][-1]
         flow_prediction_list_total[-1]+=gr.graph['hwt_flow'][0][prediction_count]
         measured_data_list_total[-1]+=gr.graph['flow_count'][-1]
         if abs(gr.graph['flow_count'][-1] - gr.graph['hwt_flow'][0][prediction_count]) > hwt_flow_deviation:
            gr.graph['detection_seq'] += 1
            gr.graph['prediction_sum'] += gr.graph['hwt_flow'][0][prediction_count] 
            gr.graph['values_lasts'].append(int(gr.graph['flow_count'][-1]))
            print len(gr.graph['values_lasts'])
            if gr.graph['detection_seq'] == num_blocks_report:
               #logger.error('Average flow count deviation %s from %s per 5 miutes during last %s minutes before %s', gr.graph['prediction_sum']/num_blocks_report,gr.graph['prediction_eval']/num_blocks_report,num_blocks_report*5,time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr.graph['last_flow'])))
               logger.warning('Average flow count: %s, average prediction count: %s per 5 miutes during last %s minutes before %s', int(sum(gr.graph['values_lasts'])/num_blocks_report),int(gr.graph['prediction_sum']/num_blocks_report),num_blocks_report*5,time.strftime('%Y-%m-%d %H:%M', time.gmtime(gr.graph['last_flow'])))
               gr.graph['detection_seq'] = 0
               gr.graph['prediction_sum'] = 0
               gr.graph['values_lasts'] = deque()
            gr.graph['flow_count'][-1] = gr.graph['hwt_flow'][0][prediction_count]
         else:
            gr.graph['detection_seq'] = 0
            gr.graph['prediction_sum'] = 0
            gr.graph['values_lasts'] = deque()
         gr.graph['prediction_count'] += 1

      #print "hwt test", gr.graph['prediction_count'] ,prediction_intervals,len(gr.graph['flow_count']) 
      if gr.graph['prediction_count'] >= prediction_intervals:
         gr.graph['hwt_flow'] = list()
         gr.graph['prediction_count'] = 0
         if 0 not in gr.graph['flow_count']:
            print "hwt test", gr.graph['prediction_count'] ,prediction_intervals,len(gr.graph['flow_count']) 
            gr.graph['hwt_flow'] = hwt.HWT(list(gr.graph['flow_count']), 24*12, 24*12*7, prediction_intervals, alpha = None,  gamma = None,delta=None, initial_values_optimization=[0.1, 0.2, 0.2])
      

def QuietPeriodProcess(gr):
   binwidth = 10
   limit = 100
   flow_list = list(gr.graph['flow_count'])
   variance_list = list()
   variance_list_hitrate = list()
   variance_list_hitrate.append(0)
   avg_flow_count = sum(flow_list) / len(flow_list)
   print "avg", avg_flow_count
   flow_list.sort()
   
   """
   for val in flow_list:
      variance_list.append(avg_flow_count-val)
   for i in variance_list:
      if i < limit:
         #print "+1"
         variance_list_hitrate[-1] += 1
      else:
         variance_list_hitrate.append(1)
         limit += 100
   plt.plot(variance_list_hitrate)
   plt.savefig('flow-variance_hitrate.png')
   plt.clf()
   #print flow_list
   med = flow_list[int(len(flow_list)/2)]
   return med + med*0.25
   """

   #testy
   
   flow_count_list = list()
   node_list = list()
   cetnost = list()
   cetnost.append(0)
   limit = 100
   for flow_count in gr.graph['flow_count']:
      print flow_count
      flow_count_list.append(flow_count)
   for node_id in gr.nodes():
      if gr.node[node_id]['permanent_addr'] == True:
         node_list = list(gr.node[node_id]['time'])
         node_list.sort()
         for i in node_list:
            if i < limit:
               cetnost[-1] += 1
               print cetnost
               print "adding"
            else:
               cetnost.append(1)
               limit += 100
         print cetnost
         plt.plot(cetnost)
         plt.savefig(node_id+'-cetnost.png')
         plt.clf()
         plt.plot(node_list)
         plt.savefig(node_id+'.png')
         plt.clf()
         limit = 100
         cetnost = list()
         cetnost.append(0)

         print node_id
         #plt.savefig(node_id+".png")
   print "max:", max(flow_count_list)
   flow_count_list.sort()
   for i in flow_count_list:
      if i < limit:
         cetnost[-1] += 1
         print cetnost
         print "adding"
      else:
         cetnost.append(1)
         limit += 100

   plt.hist(flow_list,bins=range(min(flow_list), max(flow_list) + binwidth, binwidth))
   plt.ylabel('number of 5min periods (aggregated)')
   plt.xlabel('flows/5min')
   plt.savefig('flow-cetnost.png')
   plt.clf()
   plt.plot(flow_count_list)
   plt.savefig('flow.png')
   return flow_count_list


def StrDatetime(time_str, time_format):
   return datetime.datetime.strptime(time_str, time_format)




def UpdateParameters(src_ip,dst_ip,rec,properties):
   for p in properties:
      str(getattr(rec,p))
      if p in gr.edge[src_ip][dst_ip]:
         if not str(getattr(rec,p)) in gr.edge[src_ip][dst_ip][p]:
            gr.edge[src_ip][dst_ip][p][str(getattr(rec,p))] = 1
         else:
            gr.edge[src_ip][dst_ip][p][str(getattr(rec,p))] = gr.edge[src_ip][dst_ip][p][str(getattr(rec,p))] + 1
         
      else:
         gr.edge[src_ip][dst_ip][p] = {}
         gr.edge[src_ip][dst_ip][p][str(getattr(rec,p))] = 1
      #print gr.edge[src_ip][dst_ip][p]
   return gr

def CheckIPRange(ip,ip_range):
   if ip_range is not None:
      if not any(ipaddress.ip_address(unicode(ip, "utf-8")) in p for p in ip_range):
         ip = "0.0.0.0"
         
      
   return ip


def AddEdgeTimeInfo(next_period,src_ip, dst_ip, rec,gr,properties,is_learning):
   global prediction_intervals
   if gr.has_edge(src_ip,dst_ip):
      gr[src_ip][dst_ip]['weight'] += 1
      gr[src_ip][dst_ip]['last_seen'] = rec.TIME_LAST.getSec()
      gr[src_ip][dst_ip]['time'][-1] += 1
      
      if properties is not None:
         gr = UpdateParameters(src_ip,dst_ip,rec,properties)
      
   else:
      if is_learning == False:
         logger.warning('New connection from: %s to: %s in time: %s', src_ip,dst_ip, time.strftime('%Y-%m-%d %H:%M', time.gmtime(rec.TIME_LAST.getSec())))
      gr.add_edge(src_ip,dst_ip,weight = 1,permanent_edge = False, detection_seq = 0, prediction_count = prediction_intervals,hwt_edge = deque(),values_lasts = deque(), prediction_sum=0,prediction_eval=0,last_seen = rec.TIME_LAST.getSec(), time = deque())
      while len(gr[src_ip][dst_ip]['time']) < len(gr.graph['flow_count']) - 1:
         gr[src_ip][dst_ip]['time'].append(0)
      gr[src_ip][dst_ip]['time'].append(1)
      if properties is not None:
         gr = UpdateParameters(src_ip,dst_ip,rec,properties)
   return gr

def AddNodeTimeInfo(next_period,ip,rec,gr,is_learning):
   global prediction_intervals
   if gr.has_node(ip):
         gr.node[ip]['weight'] +=1   
         gr.node[ip]['last_seen'] = rec.TIME_LAST.getSec()
         gr.node[ip]['time'][-1] += 1
   else:
      if is_learning == False:
         print "new ip ", ip
         logger.warning('New IP address: %s in time: %s', ip, time.strftime('%Y-%m-%d %H:%M', time.gmtime(rec.TIME_LAST.getSec())))
      gr.add_node(ip,weight = 1, permanent_addr = False, detection_seq = 0, prediction_count = prediction_intervals,hwt_addr=deque(),values_lasts = deque(), prediction_sum=0,prediction_eval=0, last_seen = rec.TIME_LAST.getSec(), time = deque())
      while len(gr.node[ip]['time']) < len(gr.graph['flow_count']) - 1:
         gr.node[ip]['time'].append(0)
      gr.node[ip]['time'].append(1)

   return gr

   

def AddRecord(rec, gr, properties,ip_range,next_period,first_timestamp,is_learning):
   global prediction_intervals

   src_ip = CheckIPRange(str(rec.SRC_IP),ip_range)
   dst_ip = CheckIPRange(str(rec.DST_IP),ip_range)
   #flow_count_index = (((rec.TIME_LAST.getSec() - first_timestamp) - (rec.TIME_LAST.getSec() - first_timestamp)%300)/300)%(7*24*12*2)
   #print flow_count_index
   if 'flow_count' not in gr.graph:
      gr.graph['flow_count'] = deque()
   if 'last_flow' not in gr.graph:
      gr.graph['last_flow'] = 0
   if 'prediction_count' not in gr.graph:
      gr.graph['prediction_count'] = prediction_intervals
   if 'detection_seq' not in gr.graph:
      gr.graph['detection_seq'] = 0
   if 'prediction_sum' not in gr.graph:
      gr.graph['prediction_sum'] = 0      
   if 'prediction_eval' not in gr.graph:
      gr.graph['prediction_eval'] = 0
   if 'values_lasts' not in gr.graph:
      gr.graph['values_lasts'] = deque()
   if 'hwt_flow' not in gr.graph:
      gr.graph['hwt_flow'] = list()




   #if rec.TIME_LAST.getSec() > gr.graph['last_flow']:
   gr.graph['last_flow'] = rec.TIME_LAST.getSec()
      #print gr.graph['last_flow']

   if next_period is True:
      gr.graph['flow_count'].append(1)
      if len(gr.graph['flow_count']) > (24*7*12*2):
         gr.graph['flow_count'].popleft()
   else:
      if len(gr.graph['flow_count']) == 0:
         gr.graph['flow_count'].append(1)
      else:
         gr.graph['flow_count'][-1] += 1

   if next_period == True:
      for node_id in gr.nodes():
         gr.node[node_id]['time'].append(0)
         if len(gr.node[node_id]['time']) > (24*7*12*2):
            gr.node[node_id]['time'].popleft()
      for src,dst in gr.edges():
         gr[src][dst]['time'].append(0)
         if len(gr[src][dst]['time']) > (24*7*12*2):
            gr[src][dst]['time'].popleft()
         
   gr = AddNodeTimeInfo(next_period,src_ip,rec,gr,is_learning)
   gr = AddNodeTimeInfo(next_period,dst_ip,rec,gr,is_learning)
   gr = AddEdgeTimeInfo(next_period,src_ip, dst_ip, rec,gr,properties,is_learning)
   
   
   return gr


def ParseAdditionalParams(parser,ip_range, prop_array):
   options, args = parser.parse_args()
  
   properties = options.properties
   ip_range = options.ip_range
   if properties is not None:
      prop_array = properties.split(',')
   
   if ip_range is not None:
      ip_range = ip_range.split('-')
      ip_range = list(ipaddress.summarize_address_range(ipaddress.ip_address(unicode(ip_range[0], "utf-8")), ipaddress.ip_address(unicode(ip_range[1], "utf-8"))))
   
   
   return prop_array,ip_range, options.directory, options.learning
   

def ExportData(directory = "data"):
   print "exporting data"
   print type(gr.graph['flow_count'])
   gr_to_save = nx.DiGraph(gr)
   gr_to_save.graph['flow_count'] = list(gr_to_save.graph['flow_count'])
   gr_to_save.graph['values_lasts'] = list(gr_to_save.graph['values_lasts'])
   for node_id,node_attrs in gr_to_save.nodes(data=True):
      gr_to_save.node[node_id]['permanent_addr'] = True
      for tm in gr_to_save.node[node_id]['time']:
         if tm == 0:
            gr_to_save.node[node_id]['permanent_addr'] = False
            break
      gr_to_save.node[node_id]['time'] = list(node_attrs['time'])
      gr_to_save.node[node_id]['hwt_addr'] = list(node_attrs['hwt_addr'])
      gr_to_save.node[node_id]['values_lasts'] = list()
   for src,dst,edge_attrs in gr_to_save.edges(data=True):
      gr_to_save[src][dst]['permanent_edge'] = True
      for tm in gr_to_save[src][dst]['time']:
         if tm == 0:
            gr_to_save[src][dst]['permanent_edge'] = False
            break
      gr_to_save[src][dst]['time'] = list(edge_attrs['time'])
      gr_to_save[src][dst]['hwt_edge'] = list(edge_attrs['hwt_edge'])
      gr_to_save[src][dst]['values_lasts'] = list()
   if not os.path.exists(directory):
      os.makedirs(directory)
   with open(str(directory)+"/learned.json", 'w') as outfile1:
      outfile1.write(json.dumps(json_graph.node_link_data(gr_to_save),sort_keys=True, indent=2, separators=(',', ': ')))      
   
   
def ReadLearnedData(rec,directory = "data"):
   list_shift = 0
   perm_check = True
   print directory
   if not os.path.exists(directory):
      print "Could not find learned data, start with -l parameter first."
      return
   with open(str(directory)+"/learned.json", 'r') as infile1:
      data = json.loads(infile1.read())
   graph = json_graph.node_link_graph(data, directed=True, multigraph=False, attrs={'id':'id', 'source': 'source', 'target': 'target', 'last_seen': 'last_seen', 'time': 'time', 'weight':'weight'})
   #print graph['254.158.184.235']['106.53.240.142']['time']
   for src,dst,edge_attrs in graph.edges(data=True):
      graph[src][dst]['permanent_edge'] = True
      graph[src][dst]['time'] = deque(edge_attrs['time'])
      graph[src][dst]['values_lasts'] = deque(edge_attrs['values_lasts'])
      for tm in graph[src][dst]['time']:
         if tm == 0:
            graph[src][dst]['permanent_edge'] = False
            break
      if graph[src][dst]['permanent_edge'] == False:
         graph[src][dst]['time'] = deque()
         graph[src][dst]['time'].append(0)
         graph[src][dst]['time'].append(0)


   for node_id,node_attrs in graph.nodes(data=True):
      graph.node[node_id]['time'] = deque(node_attrs['time'])
      graph.node[node_id]['permanent_addr'] = True
      graph.node[node_id]['values_lasts'] =  deque(node_attrs['values_lasts'])
      for tm in graph.node[node_id]['time']:
         if tm == 0:
            graph.node[node_id]['permanent_addr'] = False
            break
      if graph.node[node_id]['permanent_addr'] == False:
         graph.node[node_id]['time'] = deque()
         graph.node[node_id]['time'].append(0)
         graph.node[node_id]['time'].append(0)

   print graph.graph['last_flow'], rec.TIME_LAST.getSec()
   loaded_interval_index = (graph.graph['last_flow']/(60*5))%(7*24*12)
   actual_interval_index = (rec.TIME_LAST.getSec()/(60*5))%(7*24*12)
   #print graph.graph['flow_count'][-1]
   graph.graph['flow_count'] = deque(graph.graph['flow_count'])
   graph.graph['values_lasts'] = deque(graph.graph['values_lasts'])
   print  loaded_interval_index - actual_interval_index
   print graph.graph['flow_count']
   graph.graph['flow_count'].rotate(loaded_interval_index - actual_interval_index)
   for node_id, node_attrs in graph.nodes(data=True):
      graph.node[node_id]['time'].rotate(loaded_interval_index - actual_interval_index)
   for src,dst,edge_attrs in graph.edges(data=True):
      graph[src][dst]['time'].rotate(loaded_interval_index - actual_interval_index)
   print "kontrola rotace",loaded_interval_index,actual_interval_index
   return graph      




module_info = trap.CreateModuleInfo(
   "GraphFlow", # Module name
   "Graph representation of local network", # Description
   1, # Number of input interfaces
   0,  # Number of output interfaces
   parser # use previously defined OptionParser
)

# Initialize module
ifc_spec = trap.parseParams(sys.argv, module_info)

trap.init(module_info, ifc_spec)

trap.registerDefaultSignalHandler() # This is needed to allow module termination using s SIGINT or SIGTERM signal

# this module accepts all UniRec fieds -> set required format:
trap.set_required_fmt(0, trap.TRAP_FMT_UNIREC, "")

# Specifier of UniRec records will be received during libtrap negotiation
UR_Flow = None

prop_array,ip_range, directory, is_learning= ParseAdditionalParams(parser,ip_range,prop_array)






gr, first_timestamp,time_last_seen = FlowProcess(UR_Flow,is_learning, gr, prop_array, ip_range)

print is_learning
if is_learning == True:
   number_of_periods = int(((time_last_seen - time_last_seen%week_seconds) - (first_timestamp - first_timestamp%week_seconds)) /  week_seconds)
   print time_last_seen, first_timestamp
   print "num of periods",number_of_periods
   
   print number_of_periods
   #gr = PartialPeriodFlows()
   "export graph"
   #ExportData(directory)

#res = hwt.HWT(values, 24*12, 24*12*7, 1,alpha = None, beta = None, gamma = None,delta=None, initial_values_optimization=[0.1, 0.1, 0.2, 0.2])
#print res
#print gr.graph['flow_count']
#print gr.nodes()
#print gr.edges() 
print incounter
#nx.draw_networkx(gr,with_labels=True)
#p.show()
  

