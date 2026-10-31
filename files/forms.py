from django import forms
from accounts.models import File, Folder

class FileUploadForm(forms.ModelForm):

    class Meta:
        model = File
        fields = ['file', 'folder', 'encryption_type']

    def clean_file(self):
        uploaded_file = self.cleaned_data['file']

        # Maximum 50 MB
        if uploaded_file.size > 50 * 1024 * 1024:
            raise forms.ValidationError("Maximum file size is 50 MB.")

        return uploaded_file


class ShareFileForm(forms.Form):

        receiver_email=forms.EmailField(label="Recipient Email")

        permission=forms.ChoiceField(
            choices=[
                ('view','View'),
                ('download','Download')
            ]
        )
        

        expiry_date=forms.DateTimeField(required=False,widget=forms.DateTimeInput(attrs={'type':'datetime-local'}))