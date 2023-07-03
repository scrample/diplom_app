import json
import pandas as pd
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import MinMaxScaler

# Открываем файл и загружаем его содержимое
with open('secure_data.json', 'r', encoding='utf-8') as f:
    data = json.load(f)


def search_and_normilize(szi_type,szi_class):
    szi_list = []
    for antivirus in data['antivirus']:
        if antivirus['type'] == str(szi_type):
            for classes in antivirus['classes']:
                if classes['id'] == int(szi_class):
                    for szi in classes['szi_list']:
                        szi_list.append({
                            'name': szi['name'],
                            'Detection Rate': szi['Detection Rate'],
                            'Scan Speed': szi['Scan Speed'],
                            'Resource Usage': szi['Resource Usage'],
                            'Cost': szi['Cost'],
                        })
    df_data = pd.DataFrame(szi_list)
    return df_data


def select_antivirus(data, criteria):
    X = data.drop(['Antivirus'], axis=1)
    y = data[criteria]
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)
    model = RandomForestRegressor(n_estimators=100, random_state=42).fit(X_scaled, y)

    predicted_values = model.predict(X_scaled)
    pareto_frontier = []
    for i in range(len(data)):
        is_pareto = True
        for j in range(len(data)):
            if all(predicted_values[j] >= predicted_values[i]) and any(predicted_values[j] > predicted_values[i]):
                is_pareto = False
                break
        if is_pareto:
            pareto_frontier.append(i)

    best_antiviruses = data.iloc[pareto_frontier]['Antivirus'].tolist()
    best_antivirus = max(set(best_antiviruses), key=best_antiviruses.count)
    return best_antivirus

def search(antivirus_name, firewall_name):
    new_dict = {}
    with open('secure_data.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    for antivirus in data['antivirus']:
        for classes in antivirus['classes']:
            for szi in classes['szi_list']:
                if szi['name'] == antivirus_name:
                    new_dict['antivirus'] = {'cert_number': szi['cert_number'],'name': szi['name'], 'cert_time': szi['cert_time'], 'desc': szi['documents'], 'link': szi['link'] }
    
    for firewall in data['firewall']:
        for classes in firewall['classes']:
            for szi in classes['szi_list']:
                if szi['name'] == firewall_name:
                    new_dict['firewall'] = {'cert_number': szi['cert_number'],'name': szi['name'], 'cert_time': szi['cert_time'], 'desc': szi['documents'], 'link': szi['link'] }
    
    with open('szi_results.json', 'w') as f:
        json.dump(new_dict, f, indent=4)

def search_and_normilize_firewall(szi_type,szi_class):
    szi_list = []
    for antivirus in data['firewall']:
        if antivirus['type'] == str(szi_type):
            for classes in antivirus['classes']:
                if classes['id'] == int(szi_class):
                    for szi in classes['szi_list']:
                        szi_list.append({
                            'name': szi['name'],
                            'Detection Rate': szi['Detection Rate'],
                            'Scan Speed': szi['Scan Speed'],
                            'Resource Usage': szi['Resource Usage'],
                            'Cost': szi['Cost'],
                        })
    df_data = pd.DataFrame(szi_list)
    return df_data


def select_firewall(data, criteria):
    X = data.drop(['Antivirus'], axis=1)
    y = data[criteria]
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)
    model = RandomForestRegressor(n_estimators=100, random_state=42).fit(X_scaled, y)

    predicted_values = model.predict(X_scaled)
    
    pareto_frontier = []
    for i in range(len(data)):
        is_pareto = True
        for j in range(len(data)):
            if all(predicted_values[j] >= predicted_values[i]) and any(predicted_values[j] > predicted_values[i]):
                is_pareto = False
                break
        if is_pareto:
            pareto_frontier.append(i)

    best_antiviruses = data.iloc[pareto_frontier]['Antivirus'].tolist()
    best_antivirus = max(set(best_antiviruses), key=best_antiviruses.count)
    return best_antivirus        

                