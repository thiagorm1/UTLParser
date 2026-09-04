""" 
@Description: Generate Causal Graph with Multiple Attributes from Unified Output
@Date: 2024-02-29 09:36:17 
@Last Modified time: 2024-02-29 09:36:17  
"""

import networkx as nx
import matplotlib.pyplot as plt
from tqdm import tqdm
from core.graph_create import gfeature
from core.pattern import graphrule
from datetime import datetime
import logging
from core.graph_label import graphlabel
from pathlib import Path
import pandas as pd
import cfg
import ast

logging.getLogger('matplotlib.font_manager').disabled = True

# set the configuration
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

# create a logger
logger = logging.getLogger(__name__)

class UnstrGausalGraph:
    ''' build causal graphs from originally unstructured logs, include methods

    temp_graph: extract all the edges, nodes when time equals to give timestamp

    '''
    def __init__(self, outdir:str, log_type:str):
        '''
        :param outdir: the output path of unified output
        '''
        self.graphrule = graphrule.graph_attrs_json
        self.datapath = Path(outdir).joinpath("{}.log_uniform.csv".format(log_type)).as_posix()
        # self.datapath = Path(indir).joinpath("{}.log_uniform.parquet".format(log_type)).as_posix()
        self.log_type = log_type
        self.savePath = outdir
        self.entity_path = Path.cwd().parent.joinpath("core", "entity_reco")

    def data_load(self,):
        self.log_df = pd.read_csv(self.datapath)
        # self.log_df = pd.read_parquet(self.datapath)

    def comm_detect(self, G:nx.classes.digraph.DiGraph):
        ''' extract independent activity graphs
        
        '''
        comm_graphs = gfeature.comm_graph_ext(G)
        logger.info("Detect {} independent attack activities".format(len(comm_graphs)))
        return comm_graphs

    def anomaly_score(self,):
        pass
    
    def node_check(self, row: dict, key_name):
        ''' check the type of key and value
        :param row: the iterative row inside log dataframe
        :param key_name: the corresponding column inside log dataframe
        
        '''
        value = row[key_name]
        nodes = []
        # check whether value is a list first
        if isinstance(key_name, list):
            # return nodes in order
            for key in key_name:
                # like the IOCs ---- tuple, Parameters --- list
                if isinstance(row[key], tuple) or isinstance(row[key], list):
                    # recursively match value with string
                    nodes.extend([node for node in row[key] if node !='-' and \
                                  len(node.split(" "))==1 and (">" not in node)])
                else:
                    # filter nan and -
                    if row[key] != '-' and isinstance(row[key], str):
                        nodes.append(row[key])
        else:
            # check the length of corresponding value
            if isinstance(value, str) and value.strip() not in ('-', '', 'nan', 'None'):
                try:
                    value = ast.literal_eval(value)
                except Exception:
                    value = [value]
            elif not isinstance(value, list):
                value = [value] if value != '-' else []
            nodes.extend(value)
        
        return nodes

    def causal_graph(self, ):
        ''' according to defined node/edge value, attrs to build directed graphs with 
        multiple attrs
        '''
        G = nx.MultiDiGraph()
        # create node value and attrs
        if self.log_type in cfg.log_type['gen']:
            log_type = 'general'
        else:
            log_type = self.log_type
        # check if log is process log
        if log_type != "process":
            node_value_key = self.graphrule[log_type]["node"]["value"]
            node_attr_key = self.graphrule[log_type]["node"]["attrs"]

            # create edge value and attrs
            edge_value_key = self.graphrule[log_type]["edge"]["value"]
            edge_attr_key = self.graphrule[log_type]["edge"]["attrs"]

            # load the direction
            dire_key = self.graphrule[log_type]["edge"]["direc"]
        # process log 
        else:
            graph_list = []
            for option in self.graphrule[log_type].keys():
                # initialize Graph object
                G = nx.MultiDiGraph()
                node_value_key = self.graphrule[log_type][option]["node"]["value"]
                node_attr_key = self.graphrule[log_type][option]["node"]["attrs"]

                # create edge value and attrs
                edge_value_key = self.graphrule[log_type][option]["edge"]["value"]
                edge_attr_key = self.graphrule[log_type][option]["edge"]["attrs"]

                # load the direction
                dire_key = self.graphrule[log_type][option]["edge"]["direc"]
                graph_list.append(self.graph_create(G, node_value_key, node_attr_key, \
                                                    edge_value_key, edge_attr_key, dire_key))
                # compose all the sub graphs in process to one graph
                
            return nx.compose_all(graph_list)

        G = self.graph_create(G, node_value_key, node_attr_key, edge_value_key, \
                              edge_attr_key, dire_key)

        return G
    
    def graph_create(self, G, node_value_key, node_attr_key, edge_value_key, edge_attr_key, dire_key):
        
        nodes_list, edges_list = [], []
        
        def safe_literal_eval(val):
            if isinstance(val, str) and val.strip() not in ('-', '', 'nan', 'None'):
                try:
                    return ast.literal_eval(val)
                except Exception:
                    return val
            return val

        try:
            self.log_df['IOCs'] = self.log_df["IOCs"].apply(safe_literal_eval)
        except Exception as e:
            logger.warning("error occurs when converting IOCs type: %s", e)

        try:
            self.log_df['Parameters'] = self.log_df["Parameters"].apply(safe_literal_eval)
        except Exception as e:
            logger.warning("error occurs when converting Parameters type: %s", e)   

        # create the causal graph
        for _, row in tqdm(self.log_df.iterrows(), desc="making causal graph from {}".format(self.log_type)):
            nodes = self.node_check(row, node_value_key)
            # check whether nodes exist
            if len(nodes) != 0:
                node_len = len(nodes)
                # check the node attr
                if node_attr_key != {}:
                    for key, value in node_attr_key.items():
                        # only the ip has port attributes for node
                        for i in range(node_len):
                            nodes.append((nodes[i], {key: row[value][i]}))

                # check the direction and build the eßßdge
                if row[dire_key] in ["->", "-"] :
                    # create the edges
                    pairs = list(zip(nodes[::2], nodes[1::2]))
                    
                elif row[dire_key] == "<-":
                    pairs = list(zip(nodes[1::2], nodes[::2]))
                
                attrs_dict = {}
                for key, value in edge_attr_key.items():
                    if edge_value_key != "":
                        if isinstance(row[edge_value_key],str):
                            if isinstance(row[value], list):
                                row[value] = ",".join(row[value])
                            attrs_dict.update({key: row[value],
                                            'value': row[edge_value_key]})
                        else:
                            attrs_dict.update({key: row[value],
                                            'value':'-'})
                    else:
                        attrs_dict.update({key: row[value],
                                            'value':'-'})
                        
                edges_list.extend([(pair[0], pair[1], attrs_dict) for pair in pairs])
            
            else:
                continue

        # create graph
        G.add_nodes_from(nodes_list)
        G.add_edges_from(edges_list)

        return G

    def _prepare_export_graph(self, G):
        """Ensure all edges have globally unique IDs for GraphML/Gephi compatibility"""
        if isinstance(G, (nx.MultiGraph, nx.MultiDiGraph)):
            G_export = G.__class__()
            G_export.add_nodes_from(G.nodes(data=True))
            for i, (u, v, data) in enumerate(G.edges(data=True)):
                G_export.add_edge(u, v, key=f"e_{i}", **data)
            return G_export
        return G

    def graph_save(self, G, name:str):
        file_name = name if name else self.log_type
        save_path = Path(self.savePath)
        save_path.mkdir(parents=True, exist_ok=True)
        G_export = self._prepare_export_graph(G)
        nx.write_graphml_lxml(G_export, save_path.joinpath(f'{file_name}.graphml'))

        # Only generate PNG visual plot for smaller graphs to avoid high memory/CPU freeze
        if G.number_of_nodes() < 500:
            fig, ax = plt.subplots()
            graphdraw = graphlabel.GraphLabel(cfg.attr_iocs_dict, cfg.ait_iot_dict)
            graphdraw.draw_labeled_multigraph(G, "value", ax)
            fig.tight_layout()
            plt.savefig(save_path.joinpath(f'{file_name}_graph.png'))
            plt.close(fig)
        else:
            logger.info("Graph has %s nodes. Skipping PNG generation to prevent hanging.", G.number_of_nodes())

    def graph_label(self,):
        pass