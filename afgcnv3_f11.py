import sys
import af_reader_py
"""
1.94 sec before import optimisation
25 ms after
"""
file = sys.argv[1]
task = sys.argv[2]
argId = sys.argv[3]
device = "cpu"
raw_features ,att1, att2, nb_el, arg_pos, acceptance = af_reader_py.special(file, argId)
if acceptance != 2:
    if acceptance == 1:
        print("YES")
        exit(0)
    elif acceptance == 0:
        print("NO")
        exit(0)
    else:
        print("ERROR")
        exit(1)

import os
import torch
import torch.nn as nn
import torch.nn.functional as F
import dgl
from dgl.nn import GraphConv
from sklearn.preprocessing import StandardScaler

graph = dgl.graph((att1,att2), num_nodes=nb_el, device=device)
scaler = StandardScaler()
features = scaler.fit_transform(raw_features)
#features_tensor = torch.tensor(features, dtype=torch.float32)
inputs = torch.tensor(features, dtype=torch.float32)
if graph.number_of_nodes() < nb_el:
    graph.add_nodes(nb_el - graph.number_of_nodes())
graph = dgl.add_self_loop(graph)


class GCN(nn.Module):
    def __init__(self, in_features, hidden_features, fc_features, num_classes, dropout=0.5):
        super(GCN, self).__init__()
        self.layer1 = GraphConv(in_features, hidden_features)
        self.layer2 = GraphConv(hidden_features, hidden_features)
        self.layer3 = GraphConv(hidden_features, hidden_features)
        self.layer4 = GraphConv(hidden_features, hidden_features)
        self.fc = nn.Linear(fc_features, num_classes)
        self.dropout = nn.Dropout(dropout)

    def forward(self, g, inputs):
        h = self.layer1(g, inputs)
        h = F.relu(h)
        h = self.dropout(h)
        h = self.layer2(g, h + inputs)
        h = F.relu(h)
        h = self.dropout(h)
        h = self.layer3(g, h + inputs)
        h = F.relu(h)
        h = self.dropout(h)
        h = self.layer4(g, h + inputs)
        h = F.relu(h)
        h = self.dropout(h)
        h = self.fc(h)
        return h.squeeze()  # Remove the last dimension

model = GCN(11, 11, 11, 1)#.to(device)
model_path = "model_save/"+"v3-"+task+"-11_d0.5.pth"
if os.path.exists(model_path):
    model.load_state_dict(torch.load(model_path))
with torch.no_grad():
    out = model(graph, inputs)
    predicted = (torch.sigmoid(out.squeeze())>0.5).float()
    if predicted[arg_pos] == True:
        print("YES")
    else:
        print("NO")
