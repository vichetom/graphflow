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
 
gr=nx.DiGraph()
rec_buffer = []
time_window = 0
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
is_learning = None
stats_trigger = 0
minute_accuracy = 3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.FileHandler('graphflow.log'+str(datetime.datetime.now()))
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

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
parser.add_option("-t", "--time-window",
         dest="time_window",default=10,
         help="Set size of time window for keeping data in minutes. Defalut is 5min. Minimum 2 min.")
parser.add_option("-e", "--export-interval",
         dest="export_interval",default=60,
         help="Set data export interval. Default is 60 sec.")
parser.add_option("-d", "--directory", dest="directory",
         help="Set directory to save data. If parameter is not set, data are not saved.", metavar="FILE")
parser.add_option("-q", "--quiet",
         action="store_false", dest="verbose", default=True,
         help="don't print status messages to stdout")

#------------------------------------------------------


def FlowProcess(is_learning,rec, gr, prop_array, ip_range):
   global stats_trigger
   global rec_buffer
   #print rec.TIME_LAST.getSec(), stats_trigger  
   if rec.TIME_LAST.getSec() > stats_trigger - 60 and is_learning is False:
      rec_buffer.append(rec)
   else:
      gr = AddRecord(rec, gr, prop_array, ip_range)
   #print type(is_learning), is_learning
   if is_learning is False: 
      if rec.TIME_LAST.getSec() > stats_trigger:
         StructureDataProcess()
         TimeStructureDataProcess(stats_trigger)

         stats_trigger += time_window
         gr.clear()
         print "cleared"
         for record in rec_buffer:
            gr = AddRecord(record, gr, prop_array, ip_range)
         rec_buffer = []
   #print "actual", gr.nodes()
   return gr


def StrDatetime(time_str, time_format):
   return datetime.datetime.strptime(time_str, time_format)


def TimeStructureDataProcess(stats_trigger):
   #print "detailed data process", (stats_trigger - (stats_trigger%60)), time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stats_trigger - (stats_trigger%60)))
   #print day_process
   day_end,hour_end,minute_end = time.strftime('%a %H %M', time.localtime(stats_trigger - 60)).split()
   day_start,hour_end,minute_end = time.strftime('%a %H %M', time.localtime(stats_trigger - 60)).split()
   #print time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stats_trigger - 60 - time_window))
   
   time_check = stats_trigger - time_window
   while time_check <= stats_trigger - 60:
      print time_check, stats_trigger -60
      day,hour,minute = time.strftime('%a %H %M', time.gmtime(time_check - 60)).split()
      for node_learned, data_learned in gr_learned.nodes(data=True):
         
         try:
            data_learned['time'][day][hour][minute]
            #print data_learned
         except KeyError:
            continue
         #print "checking gr node"

         try:
            gr.node[node_learned]['time'][day][hour][minute]
            #print gr.node[node_learned]
         except KeyError:
            logger.warning('Node %s not in graph in time %s', node_learned,day + hour + minute)
      time_check += 60
   
   

   for node_id,node_attrs in gr.nodes(data=True):
      if node_id in gr_learned.nodes():
         for day in node_attrs['time']:
            for hour in node_attrs['time'][day]: 
               for minute in node_attrs['time'][day][hour]:
                  if day in gr_learned.node[node_id]['time']:
                     if hour in gr_learned.node[node_id]['time'][day]:
                        if minute in gr_learned.node[node_id]['time'][day][hour]:
                           #print StrDatetime(day + hour + minute,"%a%H%M") - datetime.timedelta(minutes=1),  StrDatetime(day + hour + minute,"%a%H%M") + datetime.timedelta(minutes=1)
                           minute_actual_count = node_attrs['time'][day][hour][minute] 
                           minute_learned_count = gr_learned.node[node_id]['time'][day][hour][minute]
                           if  (minute_actual_count >= (minute_learned_count - (minute_learned_count/minute_accuracy))) and (minute_actual_count <= (minute_learned_count + (minute_learned_count/minute_accuracy))):
                              logger.info('Node %s minute freqency %s OK with count accuracy %s - %s in %s',node_id, minute_actual_count, minute_learned_count - (minute_learned_count/minute_accuracy), minute_learned_count + (minute_learned_count/minute_accuracy),  day+hour+minute)
                              #print "node minute freqency",minute_actual_count,"ok with accuracy", minute_learned_count - (minute_learned_count/minute_accuracy), minute_learned_count + (minute_learned_count/minute_accuracy)
                           else:
                              logger.warning('Node %s minute freqency %s  NOT OK with count accuracy %s - %s in %s',node_id, minute_actual_count, minute_learned_count - (minute_learned_count/minute_accuracy), minute_learned_count + (minute_learned_count/minute_accuracy),  day+hour+minute)
                        else:
                           logger.warning('Node %s not in minute %s in  %s',node_id, minute,day + hour + minute)                      
                     else:
                        logger.warning('Node %s not in hour %s, in %s', node_id, hour, day + hour + minute)   
                  else:
                     logger.warning('Node %s not in day %s, in %s', node_id, day, day + hour + minute)
                   
      else:
         logger.warning('New node %s',node_id)
                     

def StructureDataProcess():
   edges_removed =set()
   addresses_removed = set()


#   addresses_removed = set(gr_learned.nodes()).difference(set(gr.nodes()))
#   edges_removed = set(gr_learned.edges()).difference(set(gr.edges()))
#   logger.warning('Addresses removed: %s',addresses_removed)
#   logger.warning('Edges removed: %s', edges_removed)

   


#--------------------------------------------------------


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


def AddEdgeTimeInfo(src_ip, dst_ip, rec,gr):
   if rec.TIME_LAST.toString("%a") not in gr[src_ip][dst_ip]['time']:
      gr[src_ip][dst_ip]['time'][rec.TIME_LAST.toString("%a")] = {}
   if rec.TIME_LAST.toString("%H") not in gr[src_ip][dst_ip]['time'][rec.TIME_LAST.toString("%a")]:
      gr[src_ip][dst_ip]['time'][rec.TIME_LAST.toString("%a")][rec.TIME_LAST.toString("%H")] = {}

   if rec.TIME_LAST.toString("%M") in gr[src_ip][dst_ip]['time'][rec.TIME_LAST.toString("%a")][rec.TIME_LAST.toString("%H")]:
      gr[src_ip][dst_ip]['time'][rec.TIME_LAST.toString("%a")][rec.TIME_LAST.toString("%H")][rec.TIME_LAST.toString("%M")] += 1
   else:
      gr[src_ip][dst_ip]['time'][rec.TIME_LAST.toString("%a")][rec.TIME_LAST.toString("%H")][rec.TIME_LAST.toString("%M")] = 1    
   return gr

def AddNodeTimeInfo(ip,rec,gr):
   if rec.TIME_LAST.toString("%a") not in gr.node[ip]['time']:
      gr.node[ip]['time'][rec.TIME_LAST.toString("%a")] = {}
   if rec.TIME_LAST.toString("%H") not in gr.node[ip]['time'][rec.TIME_LAST.toString("%a")]:
      gr.node[ip]['time'][rec.TIME_LAST.toString("%a")][rec.TIME_LAST.toString("%H")] = {}
   if rec.TIME_LAST.toString("%M") in gr.node[ip]['time'][rec.TIME_LAST.toString("%a")][rec.TIME_LAST.toString("%H")]:
      gr.node[ip]['time'][rec.TIME_LAST.toString("%a")][rec.TIME_LAST.toString("%H")][rec.TIME_LAST.toString("%M")] += 1
   else:
      gr.node[ip]['time'][rec.TIME_LAST.toString("%a")][rec.TIME_LAST.toString("%H")][rec.TIME_LAST.toString("%M")] = 1    
   return gr

def AddRecord(rec, gr, properties,ip_range):

   src_ip = CheckIPRange(str(rec.SRC_IP),ip_range)
   dst_ip = CheckIPRange(str(rec.DST_IP),ip_range)
   
   #print src_ip,dst_ip 
   if src_ip != dst_ip:
      if gr.has_node(src_ip):
         gr.node[src_ip]['weight'] +=1
         gr.node[src_ip]['last_seen'] = rec.TIME_LAST.getSec()
         gr = AddNodeTimeInfo(src_ip,rec,gr)
      else:
         gr.add_node(src_ip,weight = 1, last_seen = rec.TIME_LAST.getSec(), time = {rec.TIME_LAST.toString("%a") : {rec.TIME_LAST.toString("%H") : {rec.TIME_LAST.toString("%M") : 1}}})
      if gr.has_node(dst_ip):
         gr.node[dst_ip]['weight'] += 1
         gr.node[dst_ip]['last_seen'] = rec.TIME_LAST.getSec()
         gr = AddNodeTimeInfo(dst_ip,rec,gr)
      else:
         gr.add_node(dst_ip,weight = 1, last_seen = rec.TIME_LAST.getSec(), time = {rec.TIME_LAST.toString("%a") : {rec.TIME_LAST.toString("%H") : {rec.TIME_LAST.toString("%M") : 1}}})

      if gr.has_edge(src_ip,dst_ip):
         gr[src_ip][dst_ip]['weight'] += 1
         gr[src_ip][dst_ip]['last_seen'] = rec.TIME_LAST.getSec()
         gr = AddEdgeTimeInfo(src_ip,dst_ip, rec,gr)
         
         if properties is not None:
            gr = UpdateParameters(src_ip,dst_ip,rec,properties)
         
      else:
         gr.add_edge(src_ip,dst_ip, weight = 1, last_seen = rec.TIME_LAST.getSec(), time = {rec.TIME_LAST.toString("%a") : {rec.TIME_LAST.toString("%H") : {rec.TIME_LAST.toString("%M") : 1}}})
         if properties is not None:
            gr = UpdateParameters(src_ip,dst_ip,rec,properties)
   #print gr.edge[src_ip][dst_ip]['time'][rec.TIME_LAST.toString("%a")][rec.TIME_LAST.toString("%H")]
   return gr
      

def RemoveOldData():
   for edge in gr.edges_iter(data=True):
      if edge[2]['time'] < oldest_time:
         gr.remove_edge(edge[0],edge[1])
         n1 = nx.all_neighbors(gr, edge[0])
         n2 = nx.all_neighbors(gr, edge[1])
         if next(n1, "_empty") == "_empty":
            gr.remove_node(edge[0])
         if next(n2, "_empty") == "_empty":
            gr.remove_node(edge[1])


def ParseAdditionalParams(parser,ip_range, prop_array):
   options, args = parser.parse_args()
  
   properties = options.properties
   ip_range = options.ip_range
   if properties is not None:
      prop_array = properties.split(',')
   
   if ip_range is not None:
      ip_range = ip_range.split('-')
      ip_range = list(ipaddress.summarize_address_range(ipaddress.ip_address(unicode(ip_range[0], "utf-8")), ipaddress.ip_address(unicode(ip_range[1], "utf-8"))))
   
   
   return prop_array,ip_range, options.directory,int(options.time_window)*60, options.learning
   

def ExportData(directory = "data"):
   print "exporting data"
   
   if not os.path.exists(directory):
      os.makedirs(directory)
   with open(str(directory)+"/learned.json", 'w') as outfile1:
      outfile1.write(json.dumps(json_graph.node_link_data(gr),sort_keys=True, indent=2, separators=(',', ': ')))      
   
def ReadLearnedData(directory = "data"):
   if not os.path.exists(directory):
      print "could not find learned data"
      return
   with open(str(directory)+"/learned.json", 'r') as infile1:
      data = json.loads(infile1.read())
   graph = json_graph.node_link_graph(data, directed=True, multigraph=False, attrs={'id':'id', 'source': 'source', 'target': 'target', 'last_seen': 'last_seen', 'time': 'time', 'weight':'weight'})
   #print graph['254.158.184.235']['106.53.240.142']['time']
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

prop_array,ip_range, directory, time_window, is_learning= ParseAdditionalParams(parser,ip_range,prop_array)
print "islearning", is_learning
if is_learning == False:
   gr_learned = ReadLearnedData()



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
      UR_Flow2 = unirec.CreateTemplate("UR_Flow2", fmtspec)
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
   
   #print "cas", rec.TIME_LAST.toString("%Y-%m-%d %H:%M:%S")
   if incounter == 0:
      stats_trigger = rec.TIME_LAST.getSec() - (rec.TIME_LAST.getSec()%60)  
   

   gr = FlowProcess(is_learning,rec, gr, prop_array, ip_range)
   
   incounter+=1  

if is_learning == True:
   "export graph"
   ExportData(directory)
#print gr.nodes()
#print gr.edges() 
print incounter
#nx.draw_networkx(gr,with_labels=True)
#p.show()
  

