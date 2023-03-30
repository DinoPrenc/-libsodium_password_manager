import base64
import json
import logging
import os
import requests
import nacl.public
import tkinter.messagebox
import tkinter.filedialog

from tkinter import *
from utils import Utils


API_SERVER = os.getenv('SERVER_ADDRESS', 'http://127.0.0.1:5000')
VALID_RESPONSES = [200, 201]
SECRET_KEY = nacl.public.PrivateKey.generate()
PUBLIC_KEY = SECRET_KEY.public_key

utils = Utils(SECRET_KEY)


class Window:
    def __init__(self):
        try:
            self.handshake()
        except Exception as e:
            logging.warning("Spajanje na server nije uspijelo")
            logging.error(e)

        self.window = Tk()
        self.window.title("DPENCY password manager")
        self.window.geometry('720x350')

        # Frames
        self.option_menu_frame = Frame(self.window)
        self.online_frame = Frame(self.window)
        self.new_db_frame = Frame(self.window)
        self.new_db_record_frame = Frame(self.window)
        self.edit_db_frame = Frame(self.window)
        self.load_db_record_frame_online = Frame(self.window)
        self.list_databases_frame = Frame(self.window)
        self.sign_frame = Frame(self.window)
        self.new_db_record_frame_online = Frame(self.window)
        self.new_db_frame_online = Frame(self.window)
        self.exported_frame = Frame(self.window)
        self.export_db_frame = Frame(self.window)
        self.load_db_record_frame = Frame(self.window)
        self.menu = Frame(self.window)

        self.frames_list = [self.option_menu_frame,
                            self.online_frame,
                            self.new_db_frame,
                            self.edit_db_frame,
                            self.new_db_record_frame,
                            self.load_db_record_frame_online,
                            self.list_databases_frame,
                            self.sign_frame,
                            self.new_db_record_frame_online,
                            self.new_db_frame_online,
                            self.exported_frame,
                            self.export_db_frame,
                            self.load_db_record_frame,
                            self.menu]

        self.start_btn = Button(self.window, text='Zapocni sa radom', font='Helvetica 20', command=self.main_menu)
        self.start_btn.grid()

        self.records = []

        # run window
        self.window.grid_rowconfigure(0, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        self.window.mainloop()

    def hide_frames(self):
        for frame in self.frames_list:
            try:
                for child in frame.winfo_children():
                    child.destroy()
                frame.grid_forget()
            except Exception as e:
                logging.error(e)

    def main_menu(self):
        self.start_btn.grid_forget()
        self.hide_frames()
        self.menu.grid_forget()
        self.menu.grid()

        Label(self.menu, text='Dobrodosli u Upravitelj lozinki', font='Helvetica 18 bold').grid()

        Button(self.menu, text='Mrezni nacin', font='Helvetica 14',command=self.online_mode).grid()
        Button(self.menu, text='Izvanmrezni nacin', font='Helvetica 14',
               command=lambda: self.option_menu(self.new_db_form, self.view_and_edit_db_form, self.export_db)).grid()

    def option_menu(self, create, view, export):
        self.hide_frames()
        self.option_menu_frame.grid()

        Button(self.option_menu_frame, text='Kreiraj novu bazu', command=create).grid()
        Button(self.option_menu_frame, text='Pregledaj i Uredi postojecu bazu', command=view).grid()
        Button(self.option_menu_frame, text='Izvezi postojecu bazu', command=export).grid()
        Button(self.option_menu_frame, text='Natrag', command=self.main_menu).grid()

    def add_new_record_form(self, add_record, save_record, back):
        self.db_name_val = self.db_name_val.get()
        self.pass_value = self.pass_val.get()
        self.pass_nd_val = self.pass_nd_val.get()

        if self.pass_value != self.pass_nd_val:
            tkinter.messagebox.showinfo('Greska', 'Lozinke se ne podudaraju')
            return

        self.hide_frames()
        self.new_db_record_frame.grid()

        Label(self.new_db_record_frame, text='Unesi ime').grid(row=5)
        self.record_name_val = Entry(self.new_db_record_frame, width=35)
        self.record_name_val.grid(column=1, row=5)

        Label(self.new_db_record_frame, text='Unesi korisnicko ime').grid(row=6)
        self.record_username_val = Entry(self.new_db_record_frame, width=35)
        self.record_username_val.grid(column=1, row=6)

        Label(self.new_db_record_frame, text='Unesi lozinku').grid(row=7)
        self.record_pass_val = Entry(self.new_db_record_frame, width=35)
        self.record_pass_val.grid(column=1, row=7)

        Button(self.new_db_record_frame, text='Spremi i dodaj novi zapis', command=add_record).grid()
        Button(self.new_db_record_frame, text='Spremi i zavrsi', command=save_record).grid()
        Button(self.new_db_record_frame, text='Natrag', command=back).grid()

    def add_record(self):
        self.record_name_val = self.record_name_val.get()
        self.record_username_val = self.record_username_val.get()
        self.record_pass_val = self.record_pass_val.get()
        self.pass_value = self.pass_val.get()
        self.records.append(
            {
                'Ime': self.record_name_val,
                'Korisnicko ime': self.record_username_val,
                'Lozinka': self.record_pass_val
            }
        )

        self.hide_frames()
        self.add_new_record_form(self.add_record, self.save_record, self.new_db_form)

    def save_record(self):
        self.records.append(
            {
                'Ime': self.record_name_val.get(),
                'Korisnicko ime': self.record_username_val.get(),
                'Lozinka': self.record_pass_val.get()
            }
        )

        data = json.dumps({'data': self.records})
        encrypted_data = utils.encrypt_file(data, self.pass_value)
        try:
            with open(f'{self.db_name_val}.dpency', 'wb') as f:
                f.write(encrypted_data)
            tkinter.messagebox.showinfo('Spremljeno', 'Datoteka spremljena')
        except Exception as e:
            logging.error(e)
            tkinter.messagebox.showinfo('Greska', 'Datoteku nije moguce spremiti')

    def list_records(self, frame, data):
        self.updated_records = []
        for i, record in enumerate(data.get('data', [])):
            updated_record = {}
            Label(frame, text='Ime:').grid()
            updated_record['name'] = Entry(frame)
            updated_record['name'].insert(END, record['Ime'])
            updated_record['name'].grid()

            Label(frame, text='Korisnicko ime:').grid()
            updated_record['username'] = Entry(frame)
            updated_record['username'].insert(END, record['Korisnicko ime'])
            updated_record['username'].grid()

            Label(frame, text='Lozinka:').grid()
            updated_record['pwd'] = Entry(frame)
            updated_record['pwd'].insert(END, record['Lozinka'])
            updated_record['pwd'].grid()

            self.updated_records.append(updated_record)

    def load_local_db(self):
        self.pass_value = self.pass_val.get()
        self.db_name_val = self.db_name_val.get()
        self.hide_frames()

        self.load_db_record_frame.grid()

        try:
            with open(self.db_name_val, 'rb') as f:
                encrypted_data = f.read()
        except FileNotFoundError:
            tkinter.messagebox.showinfo('Greska', 'Datoteka nije pronadena')

        decrypted_data = utils.decrypt(encrypted_data, self.pass_value).decode()

        try:
            data = json.loads(decrypted_data)
        except Exception as e:
            tkinter.messagebox.showinfo('Greska', 'Greska prilikom ucitavanja datoteke')
            raise Exception({'error decrypting file': e})

        self.list_records(self.load_db_record_frame, data)
        Button(self.load_db_record_frame, text='Spremi promjene',
               command=lambda: self.save_updated_records(self.updated_records)).grid()
        Button(self.load_db_record_frame, text='Zavrsi', command=self.view_and_edit_db_form).grid()

    def save_updated_records(self, records):
        data = {'data': []}
        for record in records:
            data['data'].append({'Ime': record['name'].get(),
                                 'Korisnicko ime': record['username'].get(),
                                 'Lozinka': record['pwd'].get()})

        encrypted_data = utils.encrypt_file(json.dumps(data), self.pass_value)
        try:
            with open(self.db_name_val, 'wb') as f:
                f.write(encrypted_data)

            tkinter.messagebox.showinfo('Spremljeno', 'Promjene spremljene')
        except Exception as e:
            logging.error(e)
            tkinter.messagebox.showinfo('Greska', 'Promjene nisu spremljene')

    def new_db_creds_input(self, frame):
        frame.grid()
        Label(frame, text='Unesi ime baze').grid(row=0)
        self.db_name_val = Entry(frame, width=35)
        self.db_name_val.grid(column=1, row=0)
        Label(frame, text='Unesi glavnu lozinku za bazu').grid(row=1)
        self.pass_val = Entry(frame, width=35)
        self.pass_val.grid(column=1, row=1)
        Label(frame, text='Ponovo upisi lozinku:').grid(row=2)
        self.pass_nd_val = Entry(frame, width=35)
        self.pass_nd_val.grid(column=1, row=2)

    def new_db_form(self):
        self.hide_frames()

        self.new_db_creds_input(self.new_db_frame)

        Button(self.new_db_frame, text='Dodaj zapis u bazu', command=lambda: self.add_new_record_form(
            self.add_record, self.save_record, self.new_db_form)).grid(column=1)
        Button(self.new_db_frame, text='Natrag',
               command=lambda: self.option_menu(self.new_db_form, self.view_and_edit_db_form, self.export_db)
               ).grid(column=1)

    def browse_file(self):
        filename = tkinter.filedialog.askopenfilename(filetypes=(("dpency files", "*.dpency"), ("All files", "*.*")))
        self.db_name_val.insert(END, filename)  #

    def load_db_file_creds_input(self, frame):
        self.hide_frames()

        frame.grid()
        Label(frame, text='Unesi ime baze').grid(row=0)
        self.db_name_val = Entry(frame, width=35)
        self.db_name_val.grid(column=1, row=0)
        Button(frame, text='Trazi datoteku', command=self.browse_file).grid(column=2, row=0)
        Label(frame, text='Unesi glavnu lozinku za bazu').grid(column=1, row=1)
        self.pass_val = Entry(frame, width=35)
        self.pass_val.grid(column=1, row=1)

    def view_and_edit_db_form(self):
        self.load_db_file_creds_input(self.edit_db_frame)

        Button(self.edit_db_frame, text='Otvori bazu', command=self.load_local_db).grid(column=1)
        Button(self.edit_db_frame, text='Natrag',
               command=lambda: self.option_menu(self.new_db_form, self.view_and_edit_db_form, self.export_db)
               ).grid(column=1)

    def export_db(self):
        self.load_db_file_creds_input(self.export_db_frame)

        Button(self.export_db_frame, text='Izvezi bazu', command=self.export_and_save_local_db).grid(column=1)
        Button(self.export_db_frame, text='Natrag',
               command=lambda: self.option_menu(self.new_db_form, self.view_and_edit_db_form, self.export_db)
               ).grid(column=1)

    def export_and_save_local_db(self):
        self.db_name_val = self.db_name_val.get()
        self.pass_val = self.pass_val.get()
        self.hide_frames()

        self.exported_frame.grid()

        try:
            with open(self.db_name_val, 'rb') as f:
                encrypted_data = f.read()
        except FileNotFoundError:
            tkinter.messagebox.showinfo('Greska', 'Datoteka nije pronadena')

        decrypted_data = utils.decrypt(encrypted_data, self.pass_val).decode()
        try:
            data = json.loads(decrypted_data)

            with open(f'{self.db_name_val.split("/")[-1].replace(".dpency", "")}.json', 'w') as outfile:
                json.dump(data, outfile)

            tkinter.messagebox.showinfo('Spremljeno', f'Baza uspijesno izvezena u datoteku: '
                                                      f'{self.db_name_val.split("/")[-1].replace(".dpency", "")}.json')
            Button(self.export_db_frame, text='Natrag', command=self.export_db).grid()
        except Exception as e:
            tkinter.messagebox.showinfo('Greska', 'Greska prilikom ucitavanja datoteke')
            raise Exception({'error decrypting file': e})

    def online_mode(self):
        self.hide_frames()

        self.online_frame.grid()
        Button(self.online_frame, text='Prijava', command=self.online_sign_in_form).grid()
        Button(self.online_frame, text='Registracija novog racuna',
               command=self.online_sign_up_form).grid()
        Button(self.online_frame, text='Natrag', command=self.main_menu).grid()

    def online_sign_in_form(self):
        self.hide_frames()
        self.sign_frame.grid()
        Label(self.sign_frame, text='Korisnicko ime').grid()
        self.online_username = Entry(self.sign_frame, width=35)
        self.online_username.grid()

        Label(self.sign_frame, text='Lozinka').grid()
        self.online_password = Entry(self.sign_frame, width=35)
        self.online_password.grid()

        Button(self.sign_frame, text='Prijava', command=self.online_login).grid()
        Button(self.sign_frame, text='Natrag', command=self.online_mode).grid()

    def online_sign_up_form(self):
        self.hide_frames()
        self.sign_frame.grid()
        Label(self.sign_frame, text='Korisnicko ime').grid()
        self.online_username = Entry(self.sign_frame, width=35)
        self.online_username.grid()

        Label(self.sign_frame, text='Lozinka').grid()
        self.online_password = Entry(self.sign_frame, width=35)
        self.online_password.grid()

        Label(self.sign_frame, text='Ponovljena lozinka').grid()
        self.online_password_nd = Entry(self.sign_frame, width=35)
        self.online_password_nd.grid()
        Button(self.sign_frame, text='Registracija', command=self.register).grid()
        Button(self.sign_frame, text='Natrag', command=self.online_mode).grid()

    def handshake(self):
        resp = requests.get(API_SERVER + '/handshake',
                            headers={'public-key': base64.b64encode(PUBLIC_KEY._public_key).decode()}
                            )
        if resp.status_code not in VALID_RESPONSES:
            tkinter.messagebox.showinfo('Greska', resp.text)
            raise Exception
        else:
            self.server_public_key = base64.b64decode(resp.text)

    def online_login(self):
        if not self.server_public_key:
            self.handshake()
        msg = {
            'username': self.online_username.get(),
            'password': self.online_password.get()
        }
        encrypted_msg = utils.encrypt_message(msg, self.server_public_key)
        resp = requests.post(API_SERVER + '/login', json={'msg': encrypted_msg},
                             headers={'public-key': base64.b64encode(PUBLIC_KEY._public_key).decode()})
        if resp.status_code != 200:
            tkinter.messagebox.showinfo('Greska', resp.text)
            return
        resp_msg = json.loads(utils.decrypt_message(json.loads(resp.text).get('msg'), self.server_public_key))
        self.session_key = resp_msg.get('key')
        if self.session_key:
            self.option_menu(self.new_db_form_online, self.list_databases_online, self.export_db_online)

    def register(self):
        if not self.server_public_key:
            self.handshake()

        if self.online_password.get() != self.online_password_nd.get():
            tkinter.messagebox.showinfo('Greska', 'Lozinke se ne podudaraju')
            raise Exception

        msg = {
            'username': self.online_username.get(),
            'password': self.online_password.get(),
            'password_nd': self.online_password_nd.get()
        }

        encrypted_msg = utils.encrypt_message(msg, self.server_public_key)
        resp = requests.post(API_SERVER + '/signup', json={'msg': encrypted_msg},
                             headers={'public-key': base64.b64encode(PUBLIC_KEY._public_key).decode()})

        if resp.status_code not in VALID_RESPONSES:
            tkinter.messagebox.showinfo('Greska', resp.text)
            return
        resp_msg = json.loads(utils.decrypt_message(json.loads(resp.text).get('msg'), self.server_public_key))
        self.session_key = resp_msg.get('key')
        if self.session_key:
            self.option_menu(self.new_db_form_online, self.list_databases_online, self.export_db_online)
        else:
            tkinter.messagebox.showinfo('Greska', 'Pogreska prilikom registacije')
            self.online_mode()
            return

    def export_db_online(self):
        self.hide_frames()

        self.list_databases_frame.grid()
        resp = requests.get(API_SERVER + f'/{self.session_key}/list-files',
                            headers={'public-key': base64.b64encode(PUBLIC_KEY._public_key).decode()})
        if resp.status_code != 200:
            tkinter.messagebox.showinfo('Greska', resp.text)
            self.option_menu(self.new_db_form_online, self.list_databases_online, self.export_db_online)
            return
        resp_msg = json.loads(utils.decrypt_message(json.loads(resp.text).get('msg'), self.server_public_key))

        db_list = resp_msg.get('files')

        self.db_id = StringVar()
        for item in db_list:
            Radiobutton(self.list_databases_frame, text=item[1], variable=self.db_id,
                        value=item[0], indicator=0,
                        selectcolor='light blue').grid()
        self.record_pass = Label(self.list_databases_frame, text='Unesi lozinku za odabranu bazu').grid()
        self.db_pass_online = Entry(self.list_databases_frame, width=35)
        self.db_pass_online.grid()
        Button(self.list_databases_frame, text='Izvezi i spremi', command=self.export_and_save_online_db).grid()
        Button(self.list_databases_frame, text='Natrag',
               command=lambda: self.option_menu(self.new_db_form_online, self.list_databases_online,
                                                self.export_db_online)).grid()

    def export_and_save_online_db(self):
        self.db_id = self.db_id.get()
        self.db_pass_online = self.db_pass_online.get()

        encrypted_password = utils.encrypt_message(self.db_pass_online, self.server_public_key).replace('/', '_')
        resp = requests.get(API_SERVER + f'/{self.session_key}/get-file/{self.db_id}/{encrypted_password}',
                            headers={'public-key': base64.b64encode(PUBLIC_KEY._public_key).decode()}
                            )
        if resp.status_code not in VALID_RESPONSES:
            tkinter.messagebox.showinfo('Greska', resp.text)
            self.export_db_online()
            return

        resp_msg = json.loads(utils.decrypt_message(json.loads(resp.text).get('msg'), self.server_public_key))
        data = resp_msg.get('file')

        try:
            with open(f'exported-data-{self.db_id}.json', 'w') as f:
                f.write(data)
            tkinter.messagebox.showinfo('Spremljeno', f'Datoteka spremljena kao: "exported-data-{self.db_id}.json"')
        except Exception as e:
            logging.error(e)
            tkinter.messagebox.showinfo('Greska', 'Datoteku nije moguce spremiti')
            self.export_db_online()

    def new_db_form_online(self):
        self.hide_frames()

        self.new_db_creds_input(self.new_db_frame_online)

        Button(self.new_db_frame_online, text='Dodaj zapis u bazu',
               command=lambda: self.add_new_record_form(
                   self.add_record_online, self.save_record_online, self.new_db_form_online)).grid(column=1)
        Button(self.new_db_frame_online, text='Natrag',
               command=lambda: self.option_menu(self.new_db_form_online, self.list_databases_online,
                                                self.export_db_online)).grid(column=1)

    def add_record_online(self):
        self.records.append(
            {
                'Ime': self.record_name_val.get(),
                'Korisnicko ime': self.record_username_val.get(),
                'Lozinka': self.record_pass_val.get()
            }
        )
        self.new_db_record_frame_online.grid_forget()
        self.new_db_record_frame_online = None
        self.add_new_record_form(self.add_record_online, self.save_record_online, self.new_db_form_online)

    def save_record_online(self):
        self.records.append(
            {
                'Ime': self.record_name_val.get(),
                'Korisnicko ime': self.record_username_val.get(),
                'Lozinka': self.record_pass_val.get()
            }
        )
        msg = {
            'session_key': self.session_key,
            'file': base64.b64encode(json.dumps({'data': self.records}).encode()).decode(),
            'password': self.pass_value,
            'password_nd': self.pass_nd_val,
            'db_name': self.db_name_val
        }
        encrypted_msg = utils.encrypt_message(msg, self.server_public_key)
        resp = requests.post(API_SERVER + '/upload-file', json={'msg': encrypted_msg},
                             headers={'public-key': base64.b64encode(PUBLIC_KEY._public_key).decode()})
        if resp.status_code != 200:
            tkinter.messagebox.showinfo('Greska', resp.text)
            return

        tkinter.messagebox.showinfo('Spremljeno', 'Podaci spremljeni')
        self.option_menu(self.new_db_form_online, self.list_databases_online, self.export_db_online)

    def list_databases_online(self):
        self.hide_frames()

        self.list_databases_frame.grid()
        resp = requests.get(API_SERVER + f'/{self.session_key}/list-files',
                            headers={'public-key': base64.b64encode(PUBLIC_KEY._public_key).decode()})
        if resp.status_code != 200:
            tkinter.messagebox.showinfo('Greska', resp.text)
            self.option_menu(self.new_db_form_online, self.list_databases_online, self.export_db_online)
            return
        resp_msg = json.loads(utils.decrypt_message(json.loads(resp.text).get('msg'), self.server_public_key))

        db_list = resp_msg.get('files')

        self.db_id = StringVar()
        for item in db_list:
            Radiobutton(self.list_databases_frame, text=item[1], variable=self.db_id,
                        value=item[0], indicator=0,
                        selectcolor='light blue').grid()
        self.record_pass = Label(self.list_databases_frame, text='Unesi lozinku za odabranu bazu').grid()
        self.db_pass_online = Entry(self.list_databases_frame, width=35)
        self.db_pass_online.grid()
        Button(self.list_databases_frame, text='Prikazi', command=self.view_and_edit_db_form_online).grid()
        Button(self.list_databases_frame, text='Natrag',
               command=lambda: self.option_menu(self.new_db_form_online, self.list_databases_online,
                                                self.export_db_online)).grid()

    def view_and_edit_db_form_online(self):
        self.db_id = self.db_id.get()
        self.db_pass_online = self.db_pass_online.get()
        self.hide_frames()

        self.load_db_record_frame_online.grid()

        encrypted_password = utils.encrypt_message(self.db_pass_online, self.server_public_key).replace('/', '_')
        resp = requests.get(API_SERVER + f'/{self.session_key}/get-file/{self.db_id}/{encrypted_password}',
                            headers={'public-key': base64.b64encode(PUBLIC_KEY._public_key).decode()}
                            )
        if resp.status_code not in VALID_RESPONSES:
            tkinter.messagebox.showinfo('Greska', resp.text)
            self.list_databases_online()
            return

        resp_msg = json.loads(utils.decrypt_message(json.loads(resp.text).get('msg'), self.server_public_key))
        data = json.loads(resp_msg.get('file'))

        self.list_records(self.load_db_record_frame_online, data)
        Button(self.load_db_record_frame_online, text='Spremi promjene',
               command=lambda: self.save_updated_records_online(self.updated_records)).grid()
        Button(self.load_db_record_frame_online, text='Zavrsi', command=self.list_databases_online).grid()

    def save_updated_records_online(self, records):
        data = {'data': []}
        for record in records:
            data['data'].append({'Ime': record['name'].get(),
                                 'Korisnicko ime': record['username'].get(),
                                 'Lozinka': record['pwd'].get()})

        msg = {
            'session_key': self.session_key,
            'file': json.dumps(data),
            'password': self.db_pass_online
        }
        encrypted_msg = utils.encrypt_message(msg, self.server_public_key)
        resp = requests.post(API_SERVER + f'/edit/{self.db_id}', json={'msg': encrypted_msg},
                             headers={'public-key': base64.b64encode(PUBLIC_KEY._public_key).decode()})
        if resp.status_code not in VALID_RESPONSES:
            tkinter.messagebox.showinfo('Greska', resp.text)
        else:
            tkinter.messagebox.showinfo('Spremljeno', 'Promjene spremljene')


if __name__ == '__main__':
    Window()
