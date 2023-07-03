import pandas as pd
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
import json
import numpy as np
    
#Метод семантического анализа
def find_threats_depends(bdu_list):
    result = []

    threats_df = pd.read_csv('new_threats_lemm.csv')
    vul_df = pd.read_csv('vul_lemm.csv')
    # Объединение лемматизированных описаний уязвимостей в один список
    sentences = list(threats_df['Лемматизированное описание'])

    # Удаление значений, которые не являются строками
    sentences = [s for s in sentences if isinstance(s, str)]

    # Создание списка объектов TaggedDocument для каждого документа или абзаца
    documents = [TaggedDocument(doc.split(), [i]) for i, doc in enumerate(sentences)]

    #model = Doc2Vec(documents, vector_size=200, window=5, dm=0, min_count=1, workers=4, epochs=200)
    #model = Doc2Vec(documents, vector_size=30, window=10, dm=2, min_count=1, workers=4, epochs=30)
    #model = Doc2Vec(documents, vector_size=150, window=25, dm=2, min_count=1, workers=4, epochs=200) или window = 20
    model = Doc2Vec(documents, vector_size=150, window=25, dm=2, min_count=1, workers=4, epochs=200)
    #model.save('doc2vec_model.bin')

    #model = Doc2Vec.load('doc2vec_model.bin')

    for i in bdu_list:
        result_object = {}

        index = vul_df[vul_df['Идентификатор'] == i].index[0]

        line = vul_df['Лемматизированное описание'][index]

        test_list = line.split()

        vector_to_search = model.infer_vector(test_list)

        similar_documents = model.dv.most_similar([vector_to_search], topn = 1)

        result_object['vul_id'] = vul_df['Идентификатор'][index]
        result_object['vul_name'] = vul_df['Наименование уязвимости'][index]
        result_object['vul_desc'] = vul_df['Описание уязвимости'][index]
        result_object['threat_id'] = threats_df['Идентификатор УБИ'][similar_documents[0][0]]
        result_object['threat_name'] = threats_df['Наименование УБИ'][similar_documents[0][0]]
        result_object['threat_desc'] = threats_df['Описание'][similar_documents[0][0]]

        result.append(result_object)

    threat_dict = {}

    for vul in result:
        threat_id = vul['threat_id']

        vul_id = vul['vul_id']
        vul_name = vul['vul_name']
        vul_desc = vul['vul_desc']

        if threat_id not in threat_dict:
            threat_dict[threat_id] = [{'vul_id': vul_id, 'vul_name': vul_name, 'vul_desc': vul_desc}]
        else:
            threat_dict[threat_id].append({'vul_id': vul_id, 'vul_name': vul_name, 'vul_desc': vul_desc})

    new_list = []

    for threat_id, vul_ids in threat_dict.items():
        if threat_id in threats_df['Идентификатор УБИ'].values:
            threat_name = threats_df[threats_df['Идентификатор УБИ'] == threat_id]['Наименование УБИ'].values[0]
            threat_desc = threats_df[threats_df['Идентификатор УБИ'] == threat_id]['Описание'].values[0]
            new_list.append({'threat_id': threat_id, 'threat_name': threat_name, 'threat_desc': threat_desc, 'vul_ids': vul_ids})

    new_list = [{k: int(v) if isinstance(v, np.int64) else v for k, v in d.items()} for d in new_list]
    return new_list


def extract_vulns():
    bdu_list = []
    with open('hosts_vulns_results.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
    for object in data:
        for vul in object['vulns']:
            bdu_list.append(vul['ID'])

    return list(set(bdu_list))