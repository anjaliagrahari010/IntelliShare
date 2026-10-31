from django.urls import path
from . import views

urlpatterns = [

    path("upload/",views.upload_file,name="upload_file"),
    path("my-files/",views.myfiles,name="myfiles",),
    path("delete/<int:file_id>/",views.delete_file,name="delete_file"),
    path("download/<int:file_id>/",views.download_file,name="download_file"),
    path("folders/", views.my_folders, name="my_folders"),
    path("folder/create/",views.create_folder, name = "create_folder"),
    path("folder/<int:folder_id>/",views.folder_details,name="folder_detail"),
    path("folder/delete/<int:folder_id>/",views.delete_folder,name="delete_folder"),
    path("folder/<int:folder_id>/upload/",views.upload_to_folder, name="upload_to_folder"),
    path("share/<int:file_id>/",views.share_file,name="share_file"),
    path("generate_share_link/<int:file_id>/",views.generate_share_link,name="generate_share_link"),
    path("public/download/<uuid:token>/",views.download_public_file,name="download_public_file"),
    path("share/download/<uuid:token>/",views.download_shared_file,name="download_shared_file"),
    path("received_files/",views.received_file,name="received_files"),
    path("notification/",views.notification,name="notification"),
    path("shared-history/",views.shared_history,name="shared_history"),
    path("delete-all-notifications/",views.delete_all_notification,name="delete_all_notification"),
    path("share/revoke/<int:share_id>/",views.revoke_share,name="revoke_share"),
    path("request-access/<uuid:token>/",views.request_access_again,name="request_access_again"),
    path("access-requests/",views.access_requests,name="access_requests"),
    path("approve-request/<int:request_id>/",views.approve_request,name="approve_request"),
    path("reject-request/<int:request_id>/",views.reject_request,name="reject_request"),
    path("verify-integrity/<int:file_id>/", views.verify_file_integrity, name="verify_file_integrity"),
    

   
    
    
   

]