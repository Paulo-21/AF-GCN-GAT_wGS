import sys
import af_reader_py

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
from dgl.nn import GATv2Conv
from sklearn.preprocessing import StandardScaler
graph = dgl.graph((att1,att2), num_nodes=nb_el, device=device)
graph = dgl.add_self_loop(graph)
scaler = StandardScaler()
features = scaler.fit_transform(raw_features)
inputs = torch.tensor(features, dtype=torch.float32)

class GAT(nn.Module):
    def __init__(self, in_size, hid_size, out_size, heads):
        super().__init__()
        self.gat_layers = nn.ModuleList()
        # three-layer GAT
        self.gat_layers.append(
            GATv2Conv(in_size, hid_size, heads[0], activation=F.elu)
        )
        self.gat_layers.append(
            GATv2Conv(
                hid_size * heads[0],
                hid_size,
                heads[1],
                residual=True,
                activation=F.elu,
            )
        )
        self.gat_layers.append(
            GATv2Conv(
                hid_size * heads[1],
                out_size,
                heads[2],
                residual=True,
                activation=None,
            )
        )

    def forward(self, g, inputs):
        h = inputs
        for i, layer in enumerate(self.gat_layers):
            h = layer(g, h)
            if i == 2:  # last layer
                h = h.mean(1)
            else:  # other layer(s)
                h = h.flatten(1)
        return h
model = GAT(11, 5, 1, heads=[5,3,3]).to(device)
model.eval()
model_path = "model_save/v3-"+task+"-11-gatv2.pth"
if os.path.exists(model_path):
    model.load_state_dict(torch.load(model_path, map_location=device))
with torch.no_grad():
    out = model(graph, inputs)
    predicted = (torch.sigmoid(out.squeeze())>0.5).float()
    if predicted[arg_pos] == True:
        print("YES")
        exit(0)
    else:
        print("NO")
        exit(0)
