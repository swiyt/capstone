import os 
import sys
import joblib 
import pefile
import pickle

#Reminder to write about understanding PE files, theres many layers in PE files
def get_resource(file):
    resource = []
    if hasattr(file, 'DIRECTORY_ENTRY_RESOURCE'):

        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:   #check through whether theres resourcetype in directory

            if hasattr(resource_type, 'directory'):

                for resource_id in resource_id.directory.entries:
                    
                    if hasattr(resource_id, 'directory'):

                        for resource_lang in resource_id.directory.entries:

                            data = pe.get_data(resource_lang.data.struct.OffsettoData, resource_lang.data.struct.Size)
                            size = resource_lang.data.struct.Size
                            resource.append([size])

    else: 
        return f"Here's the list: {resource}"

def get_version(file):
    ver = []
    for fileinfo in file.FileInfo:  #2 statements to check whether the pe file provided contains file info. 
        if fileinfo == 'StringFileInfo':
            for st in fileinfo.StringTable: 
                for entry in st.entries.items():
                    ver[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                ver[var.entry.items([0][0])]   = var.entry.items()[0][1]
    if hasattr(file, 'VS_FIXEDFILEINFO'):
        ver['os'] = file.VS_FIXEDFILEINFO.FileOS
        ver['type'] = file.VS_FIXEDFILEINFO.FileType
        ver['file_version'] = file.VS_FIXEDFILEINFO.FileVersionLS
        ver['product_version'] = file.VS_FIXEDFILEINFO.ProductVersionLS
        ver['signature'] = file.VS_FIXEDFILEINFO.Signature
        ver['struct_version'] = file.VS_FIXEDFILEINFO.StrucVersion
    return ver 

#Headers
def extract_info(fpath):
    res = {}
    pe = pefile.PE(fpath)
    try: 
        res['Machine'] = pe.FILE_HEADER.Machine
        res['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        res['Characteristic'] = pe.FILE_HEADER.Charateristic

    except MAIN_HEADER_ERROR: 
        print(f'Error parsing file. ')

    try: 
        res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        res['SizeOfUnitializedData'] = pe.OPTIONAL_HEADER.SizeOfUnitializedData
        res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    
    except OPTIONAL_HEADER_ERROR: 
        print(f'Error parsing optional header. ')

    #Sections
    try: 
        raw_sizes = list(map(lambda x: x.get_entropy(), pe.sections))
        res['SectionsMeanRawsize'] = sum(raw_sizes) / float(len(raw_sizes))
        res['SectionsMinRawsize'] = min(raw_sizes)
        res['SectionsMaxRawsize'] = max(raw_sizes)

        virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, pe.sections))
        res['SectionsMeanVirtualsize'] = sum(virtual_sizes) / float(len(virtual_sizes))
        res['SectionsMinVirtualsize'] = min(virtual_sizes)
        res['SectionMaxVirtualsize'] = max(virtual_sizes)
    
    except SECTION_ERROR: 
        print(f'Error parsing sections. ')

    #Import
    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb'] = len(imports)
        res['ImportsNbOrdinal'] = 0
    except AttributeError:
        res['ImportsNbDLL'] = 0
        res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0
        print(f'Error importing.')

    #Export
    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        res['ExportNb'] = 0
        print(f'No export.')

    #Resources
    resources = get_resource(pe)
    res['ResourcesNb'] = len(resources)
    if len(resources) > 0:
        sizes = list(map(lambda x:x[1], resources))
        res['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else: 
        res['ResourcesMeanSize'] = 0
        res['ResourcesMinSize'] = 0
        res['ResourcesMaxSize'] = 0

    #Load configuration size
    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0


    #Version configuration size
    try:
        version_infos = get_version(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0
    return res
        
if __name__ == '__main__':
    
    #Loading the classifier.pkl and features.pkl
    clf = joblib.load('Classifier/classifier.pkl')
    features = pickle.loads(open(os.path.join('Classifier/features.pkl'),'rb').read())
    
    #extracting features from the PE file mentioned in the argument 
    data = extract_info(sys.argv[1])
    
    #matching it with the features saved in features.pkl
    pe_features = list(map(lambda x:data[x], features))
    print("Features used for classification: ", pe_features)
    
    #prediciting if the PE is malicious or not based on the extracted features
    res= clf.predict([pe_features])[0]
    print ('The file %s is %s' % (os.path.basename(sys.argv[1]),['malicious', 'legitimate'][res]))
