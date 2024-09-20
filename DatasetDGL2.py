import os
import dgl
import torch
import af_reader_py
from dgl.data import DGLDataset
from sklearn.preprocessing import StandardScaler
MAX_ARG = 200000
af_data_root = "../af_dataset/"
result_root = "../af_dataset/all_result/"

def transfom_to_graph(label_path, n, device="cpu"):
    f = open(label_path, 'r')
    data = f.read()
    target = [0.]*n
    for n in data.split(','):
        if n == '':
            continue
        target[int(n)] = 1.0
    return torch.tensor(target, requires_grad=False, device=device)

def light_get_item(af_path, features_path, device= "cpu"):
    att1, att2, nb_el = af_reader_py.reading_file_for_dgl(af_path)
    graph = dgl.graph((torch.tensor(att1),torch.tensor(att2)), num_nodes = nb_el, device=device)
    graph = dgl.add_self_loop(graph)
    inputs = torch.load(features_path, map_location="cpu")
    return graph, inputs, nb_el

def get_item(af_path, features_path, device="cpu", max_arg=MAX_ARG):
    att1, att2, nb_el = af_reader_py.reading_file_for_dgl(af_path)
    if nb_el > max_arg:
        return None, None, max_arg
    graph = dgl.graph((torch.tensor(att1),torch.tensor(att2)), num_nodes = nb_el, device=device)
    graph = dgl.add_self_loop(graph)
    raw_features = af_reader_py.compute_features_extend(af_path)
    inputs = torch.tensor(raw_features, dtype=torch.float32, device="cpu")
    torch.save(inputs, features_path)
    return graph, inputs, nb_el

class TrainingGraphDataset(DGLDataset):
    def __init__(self, af_dir, label_dir, task, max_arg=MAX_ARG, device="cpu"):
        self.label_dir = label_dir
        self.af_dir = af_dir
        self.task = task
        self.max_arg = max_arg
        self.device=device
        super().__init__(name="Af dataset")
    def __len__(self):
        return len(self.graphs)
    def process(self):
        list_year_dir = ["2017"]
        self.af_dir = af_data_root+"dataset_af"
        self.label_dir = result_root+"result_"+self.task
        self.graphs = []
        self.labels = []
        list_unique_file = []
        for year in list_year_dir:
            iter = os.listdir(self.label_dir +"_"+ year)
            for f in iter:
                true_name = f.replace(".apx", "")
                true_name = true_name.replace(".af", "")
                true_name = true_name.replace(".tgf", "")
                true_name = true_name.replace(".old", "")

                if true_name not in list_unique_file:
                    list_unique_file.append(true_name)
                    af_path = self.af_dir+"_"+year+"/"+f
                    label_path = self.label_dir+"_"+year+"/"+f
                    features_path = af_data_root+"all_features/"+year+"/"+f+".pt"
                    if os.path.exists(af_data_root+"all_features/"+year+"/"+f+".pt"):
                        graph, features, nb_el = light_get_item(af_path, features_path, device=self.device)
                    else:
                        graph, features, nb_el = get_item(af_path, features_path, device=self.device)
                    if nb_el < self.max_arg :
                        graph.ndata["feat"] = features
                        graph.ndata["label"] = transfom_to_graph(label_path, nb_el, device=self.device).unsqueeze(1)
                        self.graphs.append(graph)

    def __getitem__(self, idx:int):
        return self.graphs[idx]

class LarsMalmDataset(DGLDataset):
    def __init__(self, task, scaler,  device="cpu"):
        self.label_dir = "../AFGraphLib/AFs/solutions/"
        self.af_dir = "../AFGraphLib/AFs/"
        self.features_dir = "../AFGraphLib/AFs/features_cache_14/"
        self.device = device
        self.task = task
        self.scaler = scaler
        self.temp_feature = []
        super().__init__(name="Dataset of Lars Malm")
    def __len__(self):
        return len(self.graphs)
    def process(self):
        tot_file = 0
        self.graphs = []
        self.labels = []
        list_unique_file = []
        
        iter = os.listdir(self.af_dir)
        for f in iter:
            true_name = f.replace(".apx", "")
            true_name = true_name.replace(".af", "")
            true_name = true_name.replace(".tgf", "")
            true_name = true_name.replace(".old", "")
            
            if true_name not in list_unique_file:
                af_path = self.af_dir+f
                sem = self.task.split('-')[1]
                problem_type = self.task.split('-')[0]
                features_path = self.features_dir + f + ".pt"
                if sem == "PR":
                    label_path = self.label_dir + f +".txt"
                else:
                    label_path = self.label_dir + f +".apx.EE-"+sem
                if not os.path.exists(label_path):
                    continue
                list_unique_file.append(true_name)
                if os.path.exists(features_path):
                    print(f)
                    graph, features,  nb_el = light_get_item(af_path, features_path, device=self.device)
                else:
                    print("GET : ",f)
                    graph, features, nb_el = get_item(af_path, features_path, device=self.device)
                label = None
                if problem_type == "DC":
                    label = af_reader_py.read_lars_solution_dc(label_path, af_path)
                else :
                    label = af_reader_py.read_lars_solution_ds(label_path, af_path)
                if nb_el < MAX_ARG:
                    tot_file += 1
                    self.scaler.partial_fit(features)
                    self.temp_feature.append(features)
                    graph.ndata["label"] = torch.tensor(label, device=self.device).unsqueeze(1)
                    self.graphs.append(graph)
        print("Normalize data...")
        for (index, feat) in enumerate(self.temp_feature):
            self.graphs[index].ndata["feat"] = torch.tensor(self.scaler.transform(feat), dtype=torch.float32, device=self.device)
        self.temp_feature = None
        del self.temp_feature
        print("TOTAL number of file : ", tot_file)
    def __getitem__(self, idx:int):
        return self.graphs[idx]
class ValisationDataset(DGLDataset):
    def __init__(self, af_dir, label_dir, task, scaler, device = "cpu"):
        self.label_dir = label_dir
        self.af_dir = af_dir
        self.task = task
        self.device = device
        self.scaler = scaler
        super().__init__(name="Validation Dataset")
        
    def __len__(self):
        return len(self.graphs)
    def process(self):
        #list_year_dir = ["2017", "2023"]
        list_year_dir = ["2023"]
        self.af_dir = af_data_root+"dataset_af"
        self.label_dir = result_root+"result_"+self.task
        self.graphs = []
        self.labels = []
        list_unique_file = []
        print("device  :", self.device)
        for year in list_year_dir:
            iter = os.listdir(self.label_dir +"_"+ year)
            for f in iter:
                true_name = f.replace(".apx", "")
                true_name = true_name.replace(".af", "")
                true_name = true_name.replace(".tgf", "")
                true_name = true_name.replace(".old", "")
                if true_name not in list_unique_file:
                    af_path = self.af_dir+"_"+year+"/"+f
                    label_path = self.label_dir+"_"+year+"/"+f
                    features_path = af_data_root+"all_features_14/"+year+"/"+f+".pt"
                    list_unique_file.append(true_name)
                    if os.path.exists(features_path):
                        graph, features, nb_el = light_get_item(af_path, features_path, device=self.device)
                    else:
                        graph, features, nb_el = get_item(af_path, features_path, device=self.device)
                    if nb_el < MAX_ARG:
                        graph.ndata["feat"] = features
                        graph.ndata["label"] = transfom_to_graph(label_path, nb_el, device=self.device)
                        self.graphs.append(graph)

    def __getitem__(self, idx:int):
        return self.graphs[idx]

def test(model, task, scaler, device="cpu", rand=False):
    af_dataset = ValisationDataset(af_data_root+"dataset_af/", af_data_root+"result/",scaler=scaler, task=task, device=device)
    model.eval()
    acc_yes = 0
    acc_no = 0
    tot_el_yes = 0
    tot_el_no = 0
    mean_acc = 0
    mean_acc_yes = 0
    mean_acc_no = 0
    tot_yes_count = 0
    tot_no_count = 0
    with torch.no_grad():
        for graph in af_dataset:
            inputs = graph.ndata["feat"]
            if rand == True:
                inputs_rand = torch.randn(graph.number_of_nodes(), 128 , dtype=torch.float, device=device)
                num_rows_to_overwrite = inputs.size(0)
                num_columns_in_features = inputs.size(1)
                inputs_to_overwrite = inputs_rand.narrow(0, 0, num_rows_to_overwrite).narrow(1, 0, num_columns_in_features)
                inputs_to_overwrite.copy_(inputs)
                inputs = inputs_rand
            label = graph.ndata["label"]
            out = model(graph, inputs)
            predicted = (out.squeeze()>0.5).float()
            one_acc_yes = sum(element1 == element2 == 1.0  for element1, element2 in zip(predicted, label)).item()
            one_acc_no = sum(element1 == element2 == 0.0   for element1, element2 in zip(predicted, label)).item()
            acc_yes += one_acc_yes
            acc_no += one_acc_no
            tot_yes = sum(element1 == 1.0  for element1 in label).item()
            tot_no = sum(element1 == 0.0   for element1 in label).item()
            tot_el_yes += tot_yes
            tot_el_no += tot_no
            mean_acc += ((one_acc_yes+one_acc_no)/(tot_yes+tot_no))
            if tot_yes != 0:
                mean_acc_yes += ((one_acc_yes)/(tot_yes))
                tot_yes_count += 1
            if tot_no != 0:
                mean_acc_no += ((one_acc_no)/(tot_no))
                tot_no_count += 1

    print("acc : ", (acc_yes+acc_no)/(tot_el_no+tot_el_yes) ,"acc yes : ", acc_yes/tot_el_yes, "acc no : ", acc_no/tot_el_no )
    print("acc mean : ", mean_acc/len(af_dataset), " acc mean y : ", mean_acc_yes/tot_yes_count, " acc mean no : ", mean_acc_no/tot_no_count)
    print(task)
