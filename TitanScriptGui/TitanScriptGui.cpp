#include "stdafx.h"
#include "Form1.h"

using namespace TitanScriptGui;

[STAThreadAttribute]
int main(array<System::String ^> ^args)
{
    if ( !ExtensionManagerIsPluginLoaded( "TitanScript" ) || !ExtensionManagerIsPluginEnabled( "TitanScript" ) ) {
        System::Windows::Forms::MessageBox::Show("TitanScript failed to load!", "[ERROR]", MessageBoxButtons::OK, MessageBoxIcon::Error);
        return -1;
    }

    // Aktivieren visueller Effekte von Windows XP, bevor Steuerelemente erstellt werden
    Application::EnableVisualStyles();
    Application::SetCompatibleTextRenderingDefault(false);

    // Hauptfenster erstellen und ausführen
    Application::Run(gcnew Form1());

    return 0;
}
