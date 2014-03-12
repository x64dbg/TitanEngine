#pragma once

#include "TitanEngine.h"
#include "TitanScript.h"

namespace TitanScriptGui {

using namespace System;
using namespace System::ComponentModel;
using namespace System::Collections;
using namespace System::Windows::Forms;
using namespace System::Data;
using namespace System::Drawing;
using namespace System::Runtime::InteropServices;

public delegate void log_callback_delegate( const char* str, eLogType log_type );
/// <summary>
/// Zusammenfassung für Form1
/// </summary>
public ref class Form1 : public System::Windows::Forms::Form
{
public:
    Form1(void)
    {
        InitializeComponent();
        InitializeTitanScript();
    }

protected:
    /// <summary>
    /// Verwendete Ressourcen bereinigen.
    /// </summary>
    ~Form1()
    {
        if (components)
        {
            delete components;
        }
    }
private:
    System::Windows::Forms::TextBox^  textBox_targetPath;
protected:
private:

protected:
private:
    System::Windows::Forms::Label^  label1;
private:
    System::Windows::Forms::Button^  openTarget;
private:

private:

private:
    System::Windows::Forms::Label^  label2;
private:
    System::Windows::Forms::TextBox^  textBox_scriptPath;
private:
    System::Windows::Forms::Button^  openScript;
private:

private:

private:

private:
    System::Windows::Forms::GroupBox^  groupBox1;
private:
    System::Windows::Forms::TextBox^  logBox;
private:

private:
    System::Windows::Forms::Button^  run;
private:

private:
    System::Windows::Forms::OpenFileDialog^  openFileDialog1;

private:
    tScripterLoadFileA load_file;
    tScripterExecuteWithTitanMistA exec;
    tScripterSetLogCallback set_log_callback;

    log_callback_delegate^ logdelegate;

private:
    /// <summary>
    /// Erforderliche Designervariable.
    /// </summary>
    System::ComponentModel::Container ^components;

    #pragma region Windows Form Designer generated code
    /// <summary>
    /// Erforderliche Methode für die Designerunterstützung.
    /// Der Inhalt der Methode darf nicht mit dem Code-Editor geändert werden.
    /// </summary>
    void InitializeComponent(void)
    {
        this->textBox_targetPath = (gcnew System::Windows::Forms::TextBox());
        this->label1 = (gcnew System::Windows::Forms::Label());
        this->openTarget = (gcnew System::Windows::Forms::Button());
        this->label2 = (gcnew System::Windows::Forms::Label());
        this->textBox_scriptPath = (gcnew System::Windows::Forms::TextBox());
        this->openScript = (gcnew System::Windows::Forms::Button());
        this->groupBox1 = (gcnew System::Windows::Forms::GroupBox());
        this->logBox = (gcnew System::Windows::Forms::TextBox());
        this->run = (gcnew System::Windows::Forms::Button());
        this->openFileDialog1 = (gcnew System::Windows::Forms::OpenFileDialog());
        this->groupBox1->SuspendLayout();
        this->SuspendLayout();
        //
        // textBox_targetPath
        //
        this->textBox_targetPath->Location = System::Drawing::Point(60, 12);
        this->textBox_targetPath->Name = L"textBox_targetPath";
        this->textBox_targetPath->Size = System::Drawing::Size(168, 20);
        this->textBox_targetPath->TabIndex = 0;
        //
        // label1
        //
        this->label1->AutoSize = true;
        this->label1->Location = System::Drawing::Point(10, 12);
        this->label1->Name = L"label1";
        this->label1->Size = System::Drawing::Size(44, 13);
        this->label1->TabIndex = 1;
        this->label1->Text = L"[Target]";
        //
        // openTarget
        //
        this->openTarget->Location = System::Drawing::Point(234, 12);
        this->openTarget->Name = L"openTarget";
        this->openTarget->Size = System::Drawing::Size(75, 23);
        this->openTarget->TabIndex = 2;
        this->openTarget->Text = L"[Open...]";
        this->openTarget->UseVisualStyleBackColor = true;
        this->openTarget->Click += gcnew System::EventHandler(this, &Form1::openTarget_Click);
        //
        // label2
        //
        this->label2->AutoSize = true;
        this->label2->Location = System::Drawing::Point(10, 44);
        this->label2->Name = L"label2";
        this->label2->Size = System::Drawing::Size(40, 13);
        this->label2->TabIndex = 3;
        this->label2->Text = L"[Script]";
        //
        // textBox_scriptPath
        //
        this->textBox_scriptPath->Location = System::Drawing::Point(60, 44);
        this->textBox_scriptPath->Name = L"textBox_scriptPath";
        this->textBox_scriptPath->Size = System::Drawing::Size(168, 20);
        this->textBox_scriptPath->TabIndex = 4;
        //
        // openScript
        //
        this->openScript->Location = System::Drawing::Point(234, 44);
        this->openScript->Name = L"openScript";
        this->openScript->Size = System::Drawing::Size(75, 23);
        this->openScript->TabIndex = 5;
        this->openScript->Text = L"[Open...]";
        this->openScript->UseVisualStyleBackColor = true;
        this->openScript->Click += gcnew System::EventHandler(this, &Form1::openScript_Click);
        //
        // groupBox1
        //
        this->groupBox1->Controls->Add(this->logBox);
        this->groupBox1->Location = System::Drawing::Point(13, 70);
        this->groupBox1->Name = L"groupBox1";
        this->groupBox1->Size = System::Drawing::Size(294, 285);
        this->groupBox1->TabIndex = 6;
        this->groupBox1->TabStop = false;
        this->groupBox1->Text = L"[Log]";
        //
        // logBox
        //
        this->logBox->Location = System::Drawing::Point(6, 19);
        this->logBox->Multiline = true;
        this->logBox->Name = L"logBox";
        this->logBox->Size = System::Drawing::Size(282, 260);
        this->logBox->TabIndex = 0;
        //
        // run
        //
        this->run->Location = System::Drawing::Point(122, 361);
        this->run->Name = L"run";
        this->run->Size = System::Drawing::Size(75, 23);
        this->run->TabIndex = 7;
        this->run->Text = L"[Run]";
        this->run->UseVisualStyleBackColor = true;
        this->run->Click += gcnew System::EventHandler(this, &Form1::run_Click);
        //
        // openFileDialog1
        //
        this->openFileDialog1->FileName = L"openFileDialog1";
        //
        // Form1
        //
        this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
        this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
        this->ClientSize = System::Drawing::Size(319, 389);
        this->Controls->Add(this->run);
        this->Controls->Add(this->groupBox1);
        this->Controls->Add(this->openScript);
        this->Controls->Add(this->textBox_scriptPath);
        this->Controls->Add(this->label2);
        this->Controls->Add(this->openTarget);
        this->Controls->Add(this->label1);
        this->Controls->Add(this->textBox_targetPath);
        this->Name = L"Form1";
        this->Text = L"TitanScriptGUI";
        this->groupBox1->ResumeLayout(false);
        this->groupBox1->PerformLayout();
        this->ResumeLayout(false);
        this->PerformLayout();

    }
    #pragma endregion

    void InitializeTitanScript(void) {
        load_file = GetTSFunctionPointer( LoadFileA );
        exec = GetTSFunctionPointer( ExecuteWithTitanMistA );
        set_log_callback = GetTSFunctionPointer( SetLogCallback );

        //register log callback
        logdelegate = gcnew log_callback_delegate(this, &Form1::log_callback);
        IntPtr thunk = System::Runtime::InteropServices::Marshal::GetFunctionPointerForDelegate(logdelegate);
        set_log_callback((fLogCallback)(void*)thunk);
    }

private:
    System::Void openTarget_Click(System::Object^  sender, System::EventArgs^  e) {
        if(openFileDialog1->ShowDialog() == System::Windows::Forms::DialogResult::OK) {
            textBox_targetPath->Text = openFileDialog1->FileName;
        }
    }
private:
    System::Void openScript_Click(System::Object^  sender, System::EventArgs^  e) {
        if(openFileDialog1->ShowDialog() == System::Windows::Forms::DialogResult::OK) {
            textBox_scriptPath->Text = openFileDialog1->FileName;
        }
    }
private:
    System::Void run_Click(System::Object^  sender, System::EventArgs^  e) {
        logBox->Clear();

        const char* scriptPath = (const char*)(void*) Marshal::StringToHGlobalAnsi(textBox_scriptPath->Text);
        const char* targetPath = (const char*)(void*) Marshal::StringToHGlobalAnsi(textBox_targetPath->Text);

        if(!load_file(scriptPath)) {
            logBox->AppendText("[Error] Couldnt load the script");
        }

        bool ret = exec(targetPath, "dump.exe");

        Marshal::FreeHGlobal(IntPtr((void*)scriptPath));
        Marshal::FreeHGlobal(IntPtr((void*)targetPath));
    }

private:
    void log_callback( const char* str, eLogType log_type ) {
        logBox->AppendText(gcnew String(str));
    }

};


}

