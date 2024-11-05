#====================================== BIBLIOTECAS ======================================#
import hashlib
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from cryptography.fernet import Fernet
from datetime import datetime
import tkinter as tk
from tkinter import messagebox

#====================================== FERNET ======================================#
key = Fernet.generate_key()
fernet = Fernet(key)

#====================================== CONFIG MONGO ======================================#
uri = "mongodb+srv://lissamajeau:123@projeto.yf3yh.mongodb.net/?retryWrites=true&w=majority&appName=projeto"
client = MongoClient(uri, server_api=ServerApi('1'))
db = client['pagamento_sistema']

#====================================== HASH DA TRANSAÇÃO ======================================#
def hash_transacao(transacao): 
    transacao_str = f"{transacao['_id']}{transacao['valor']}{transacao['numero_cartao']}{transacao['cvv']}{transacao['validade']}"
    return hashlib.sha256(transacao_str.encode()).hexdigest()

#====================================== HASH DA SENHA ======================================#
def hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()

#====================================== TOKEN TEMPORÁRIO ======================================#
def token_temporario(expiracao_segundos=300):
    #gera um token contendo a data de criação e uma validade em segundos
    data_criacao = datetime.now().timestamp()
    token_dados = f"{data_criacao}|{expiracao_segundos}"
    token = fernet.encrypt(token_dados.encode()).decode()  #criptografa com Fernet para gerar o token
    return token

def verificar_token(token):
    try:
        #descriptografa o token
        token_dados = fernet.decrypt(token.encode()).decode()
        data_criacao, expiracao_segundos = token_dados.split("|")
        
        #calcula o tempo de validade do token
        tempo_atual = datetime.now().timestamp()
        if (tempo_atual - float(data_criacao)) > int(expiracao_segundos):
            return False  #token expirado

        return True  #token válido
    except Exception as e:
        print("Erro ao verificar o token:", e)
        return False

#====================================== REGISTRO DO CLIENTE ======================================#
def registrar_cliente():
    nome = nome_entry.get().strip()
    cpf = cpf_entry.get().strip()
    senha = senha_entry.get().strip()

    if not nome or not all(char.isalpha() or char.isspace() for char in nome):
        messagebox.showerror("Erro", "Nome inválido. Digite novamente.")
        return
    if not cpf.isdigit():
        messagebox.showerror("Erro", "CPF inválido. Digite apenas números.")
        return
    if not senha:
        messagebox.showerror("Erro", "Senha não pode estar em branco.")
        return
    
    collection_name = f'{cpf}'
    if collection_name in db.list_collection_names():
        messagebox.showinfo("Aviso", "Seu registro já existe.")
        return

    senha_crip = hash_senha(senha) #função do hash da senha 

    registro_cliente = {
        "_id": cpf,
        "nome": nome,
        "senha": senha_crip
    }
    
    try:
        db[collection_name].insert_one(registro_cliente)
        messagebox.showinfo("Sucesso", "Registro realizado com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", f"Falha ao registrar: {e}")

#====================================== TRANSAÇÃO ======================================#
def realizar_transacao():
    cpf = cpf_transacao_entry.get().strip()
    identificacao = id_entry.get().strip()
    valor = valor_entry.get().strip()
    numero_cartao = numero_cartao_entry.get().strip()
    cvv = cvv_entry.get().strip()
    validade = validade_entry.get().strip()

    if not cpf.isdigit() or not identificacao.isdigit() or not valor.isdigit() or not numero_cartao.isdigit() or not cvv.isdigit():
        messagebox.showerror("Erro", "Digite apenas números para CPF, ID, valor, número do cartão e CVV.")
        return
    if not (13 <= len(numero_cartao) <= 19):
        messagebox.showerror("Erro", "O número do cartão deve ter entre 13 e 19 dígitos.")
        return
    if len(cvv) not in [3, 4]:
        messagebox.showerror("Erro", "O CVV deve ter 3 ou 4 dígitos.")
        return

    #verificação de validade do cartão no formato MM/AA
    try:
        validade_dt = datetime.strptime(validade, "%m/%y")
        if validade_dt < datetime.now():
            messagebox.showerror("Erro", "O cartão está expirado.")
            return
    except ValueError:
        messagebox.showerror("Erro", "A validade deve estar no formato MM/AA e representar uma data válida.")
        return
        
    collection_name = f'{cpf}'    
    if collection_name not in db.list_collection_names():
        messagebox.showinfo("Aviso", "Seu registro não foi cadastrado. Registre-se primeiro.")
        return

    collection = db[collection_name]
    if collection.find_one({"_id": identificacao}):
        messagebox.showerror("Erro", "ID já existe no banco de dados. Escolha outro ID.")
        return

    #verifica o token temporário
    token = token_entry.get().strip()
    if not verificar_token(token):
        messagebox.showerror("Erro", "Token inválido ou expirado.")
        return

    #criptografando os dados
    numero_cartao_crip = fernet.encrypt(numero_cartao.encode())
    cvv_crip = fernet.encrypt(cvv.encode())
    validade_crip = fernet.encrypt(validade.encode())
    data_hora_atual = datetime.now()

    #preparando a transação para o banco de dados
    transacao = {
        "_id": identificacao,
        "valor": valor,
        "data_hora": data_hora_atual,
        "numero_cartao": numero_cartao_crip,
        "cvv": cvv_crip,
        "validade": validade_crip,
        "hash": ""
    }
    transacao['hash'] = hash_transacao(transacao)

    try:
        collection.insert_one(transacao)
        messagebox.showinfo("Sucesso", "Transação realizada com sucesso!")
    except Exception as e:
        messagebox.showerror("Erro", f"Falha ao salvar a transação: {e}")

#====================================== HISTÓRICO ======================================#
def verificar_historico():
    cpf = cpf_historico_entry.get().strip()
    senha = senha_historico_entry.get().strip()

    if not cpf.isdigit() or not cpf:
        messagebox.showerror("Erro", "CPF inválido. Digite apenas números.")
        return
    if not senha:
        messagebox.showerror("Erro", "Senha não pode estar em branco.")
        return

    collection_name = f'{cpf}'    
    if collection_name not in db.list_collection_names():
        messagebox.showinfo("Aviso", "Registro não encontrado. Registre-se primeiro.")
        return

    collection = db[collection_name]
    cliente = collection.find_one({"_id": cpf})

    #verifica a senha 
    if not cliente or cliente['senha'] != hash_senha(senha): #função hash da senha
        messagebox.showerror("Erro", "Senha incorreta. Acesso ao histórico negado.")
        return

    #recupera e exibe o histórico se a senha tiver correta
    registros = collection.find({"valor": {"$exists": True}}) #verifica se existe o campo valor (não vai retornar o registro do cliente, pq nao possui essa variavel)
    historico_text.delete("1.0", tk.END)  #limpa o campo antes de exibir o histórico

    for registro in registros:
        data_hora = registro['data_hora'].strftime("%d/%m/%Y %H:%M:%S")
        historico_text.insert(tk.END, f"ID: {registro['_id']}, Valor: {registro['valor']}, Data e Hora: {data_hora}\n")
    messagebox.showinfo("Sucesso", "Histórico exibido com sucesso.")

#====================================== GERAR TOKEN ======================================#
def gerar_token():
    token_valor = token_temporario() #gera e exibe o token temporário
    token_display.delete("1.0", tk.END)  #limpa o campo de exibição do token
    token_display.insert(tk.END, token_valor)  #insere o token gerado

        
#====================================== TKINTER ======================================#
root = tk.Tk()
root.title("Sistema de Pagamentos")

#seção de Registro
tk.Label(root, text="Registro de Cliente").grid(row=0, column=0, columnspan=2, pady=10)
tk.Label(root, text="Nome Completo:").grid(row=1, column=0)
nome_entry = tk.Entry(root)
nome_entry.grid(row=1, column=1)

tk.Label(root, text="CPF:").grid(row=2, column=0)
cpf_entry = tk.Entry(root)
cpf_entry.grid(row=2, column=1)

tk.Label(root, text="Senha:").grid(row=3, column=0)
senha_entry = tk.Entry(root, show="*")
senha_entry.grid(row=3, column=1)

tk.Button(root, text="Registrar", command=registrar_cliente).grid(row=4, column=0, columnspan=2, pady=5)

#seção de Transação
tk.Label(root, text="Realizar Transação").grid(row=5, column=0, columnspan=2, pady=10)
tk.Label(root, text="CPF:").grid(row=6, column=0)
cpf_transacao_entry = tk.Entry(root)
cpf_transacao_entry.grid(row=6, column=1)

tk.Label(root, text="ID da Compra:").grid(row=7, column=0)
id_entry = tk.Entry(root)
id_entry.grid(row=7, column=1)

tk.Label(root, text="Valor:").grid(row=8, column=0)
valor_entry = tk.Entry(root)
valor_entry.grid(row=8, column=1)

tk.Label(root, text="Número do Cartão:").grid(row=9, column=0)
numero_cartao_entry = tk.Entry(root)
numero_cartao_entry.grid(row=9, column=1)

tk.Label(root, text="CVV:").grid(row=10, column=0)
cvv_entry = tk.Entry(root, show="*")
cvv_entry.grid(row=10, column=1)

tk.Label(root, text="Validade (MM/AA):").grid(row=11, column=0)
validade_entry = tk.Entry(root)
validade_entry.grid(row=11, column=1)

tk.Label(root, text="Token:").grid(row=12, column=0)
token_entry = tk.Entry(root)
token_entry.grid(row=12, column=1)

#botão para gerar token e área de exibição do token gerado
tk.Button(root, text="Gerar Token", command=gerar_token).grid(row=13, column=0, pady=5)
token_display = tk.Text(root, height=1, width=80)
token_display.grid(row=13, column=1)

tk.Button(root, text="Confirmar Transação", command=realizar_transacao).grid(row=14, column=0, columnspan=2, pady=5)

#seção de Histórico
tk.Label(root, text="Verificar Histórico de Transações").grid(row=15, column=0, columnspan=2, pady=10)
tk.Label(root, text="CPF:").grid(row=16, column=0)
cpf_historico_entry = tk.Entry(root)
cpf_historico_entry.grid(row=16, column=1)

tk.Label(root, text="Senha:").grid(row=17, column=0)
senha_historico_entry = tk.Entry(root, show="*")
senha_historico_entry.grid(row=17, column=1)

tk.Button(root, text="Verificar Histórico", command=verificar_historico).grid(row=18, column=0, columnspan=2, pady=5)

#area para exibir o histórico
historico_text = tk.Text(root, height=10, width=70)
historico_text.grid(row=19, column=0, columnspan=2)

root.mainloop()




