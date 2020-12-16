using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.Extensions.Options;
using Umbraco.Core.Composing;
using Umbraco.Core.Configuration.Models;
using Umbraco.Core.Events;
using Umbraco.Core.Models;
using Umbraco.Core.Models.Entities;
using Umbraco.Core.Models.Membership;
using Umbraco.Core.Security;
using Umbraco.Core.Services;
using Umbraco.Core.Services.Implement;
using Umbraco.Extensions;

using Umbraco.Net;

namespace Umbraco.Core.Compose
{
    public sealed class AuditEventsComponent : IComponent
    {
        private readonly IAuditService _auditService;
        private readonly IUserService _userService;
        private readonly IEntityService _entityService;
        private readonly IIpResolver _ipResolver;
        private readonly IBackOfficeSecurityAccessor _backOfficeSecurityAccessor;
        private readonly GlobalSettings _globalSettings;

        public AuditEventsComponent(IAuditService auditService, IUserService userService, IEntityService entityService, IIpResolver ipResolver, IOptions<GlobalSettings> globalSettings, IBackOfficeSecurityAccessor backOfficeSecurityAccessor)
        {
            _auditService = auditService;
            _userService = userService;
            _entityService = entityService;
            _ipResolver = ipResolver;
            _backOfficeSecurityAccessor = backOfficeSecurityAccessor;
            _globalSettings = globalSettings.Value;
        }

        private IUser CurrentPerformingUser
        {
            get
            {
                // TODO: Test and make sure this works.
                IUser user = _backOfficeSecurityAccessor.BackOfficeSecurity.CurrentUser;
                return user ?? UnknownUser(_globalSettings);
            }
        }

        private string PerformingIp => _ipResolver.GetCurrentRequestIpAddress();

        public void Initialize()
        {
            UserService.SavedUserGroup += OnSavedUserGroupWithUsers;

            UserService.SavedUser += OnSavedUser;
            UserService.DeletedUser += OnDeletedUser;
            UserService.UserGroupPermissionsAssigned += UserGroupPermissionAssigned;

            MemberService.Saved += OnSavedMember;
            MemberService.Deleted += OnDeletedMember;
            MemberService.AssignedRoles += OnAssignedRoles;
            MemberService.RemovedRoles += OnRemovedRoles;
            MemberService.Exported += OnMemberExported;
        }

        public void Terminate()
        {
            UserService.SavedUserGroup -= OnSavedUserGroupWithUsers;

            UserService.SavedUser -= OnSavedUser;
            UserService.DeletedUser -= OnDeletedUser;
            UserService.UserGroupPermissionsAssigned -= UserGroupPermissionAssigned;

            MemberService.Saved -= OnSavedMember;
            MemberService.Deleted -= OnDeletedMember;
            MemberService.AssignedRoles -= OnAssignedRoles;
            MemberService.RemovedRoles -= OnRemovedRoles;
            MemberService.Exported -= OnMemberExported;
        }

        public static IUser UnknownUser(GlobalSettings globalSettings) => new User(globalSettings) { Id = Constants.Security.UnknownUserId, Name = Constants.Security.UnknownUserName, Email = "" };

        private IUser GetPerformingUser(int userId)
        {
            IUser found = userId >= 0 ? _userService.GetUserById(userId) : null;
            return found ?? UnknownUser(_globalSettings);
        }

        private string FormatEmail(IMember member) => member == null ? string.Empty : member.Email.IsNullOrWhiteSpace() ? string.Empty : $"<{member.Email}>";

        private string FormatEmail(IUser user) => user == null ? string.Empty : user.Email.IsNullOrWhiteSpace() ? string.Empty : $"<{user.Email}>";

        private void OnRemovedRoles(IMemberService sender, RolesEventArgs args)
        {
            IUser performingUser = CurrentPerformingUser;
            var roles = string.Join(", ", args.Roles);
            var members = sender.GetAllMembers(args.MemberIds).ToDictionary(x => x.Id, x => x);
            foreach (var id in args.MemberIds)
            {
                members.TryGetValue(id, out IMember member);
                _auditService.Write(performingUser.Id, $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}", PerformingIp,
                    DateTime.UtcNow,
                    -1, $"Member {id} \"{member?.Name ?? "(unknown)"}\" {FormatEmail(member)}",
                    "umbraco/member/roles/removed", $"roles modified, removed {roles}");
            }
        }

        private void OnAssignedRoles(IMemberService sender, RolesEventArgs args)
        {
            IUser performingUser = CurrentPerformingUser;
            var roles = string.Join(", ", args.Roles);
            var members = sender.GetAllMembers(args.MemberIds).ToDictionary(x => x.Id, x => x);
            foreach (var id in args.MemberIds)
            {
                members.TryGetValue(id, out IMember member);
                _auditService.Write(performingUser.Id, $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}", PerformingIp,
                    DateTime.UtcNow,
                    -1, $"Member {id} \"{member?.Name ?? "(unknown)"}\" {FormatEmail(member)}",
                    "umbraco/member/roles/assigned", $"roles modified, assigned {roles}");
            }
        }

        private void OnMemberExported(IMemberService sender, ExportedMemberEventArgs exportedMemberEventArgs)
        {
            IUser performingUser = CurrentPerformingUser;
            IMember member = exportedMemberEventArgs.Member;

            _auditService.Write(performingUser.Id, $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}", PerformingIp,
                DateTime.UtcNow,
                -1, $"Member {member.Id} \"{member.Name}\" {FormatEmail(member)}",
                "umbraco/member/exported", "exported member data");
        }

        private void OnSavedUserGroupWithUsers(IUserService sender, SaveEventArgs<UserGroupWithUsers> saveEventArgs)
        {
            IUser performingUser = CurrentPerformingUser;
            foreach (UserGroupWithUsers groupWithUser in saveEventArgs.SavedEntities)
            {
                IUserGroup group = groupWithUser.UserGroup;

                var dp = string.Join(", ", ((UserGroup)group).GetWereDirtyProperties());
                var sections = ((UserGroup)group).WasPropertyDirty("AllowedSections")
                    ? string.Join(", ", group.AllowedSections)
                    : null;
                var perms = ((UserGroup)group).WasPropertyDirty("Permissions")
                    ? string.Join(", ", group.Permissions)
                    : null;

                var sb = new StringBuilder();
                sb.Append($"updating {(string.IsNullOrWhiteSpace(dp) ? "(nothing)" : dp)};");
                if (sections != null)
                {
                    sb.Append($", assigned sections: {sections}");
                }

                if (perms != null)
                {
                    if (sections != null)
                    {
                        sb.Append(", ");
                    }

                    sb.Append($"default perms: {perms}");
                }

                _auditService.Write(performingUser.Id, $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}", PerformingIp,
                    DateTime.UtcNow,
                    -1, $"User Group {group.Id} \"{group.Name}\" ({group.Alias})",
                    "umbraco/user-group/save", $"{sb}");

                // now audit the users that have changed
                foreach (IUser user in groupWithUser.RemovedUsers)
                {
                    _auditService.Write(performingUser.Id, $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}", PerformingIp,
                        DateTime.UtcNow,
                        user.Id, $"User \"{user.Name}\" {FormatEmail(user)}",
                        "umbraco/user-group/save", $"Removed user \"{user.Name}\" {FormatEmail(user)} from group {group.Id} \"{group.Name}\" ({group.Alias})");
                }

                foreach (IUser user in groupWithUser.AddedUsers)
                {
                    _auditService.Write(performingUser.Id, $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}", PerformingIp,
                        DateTime.UtcNow,
                        user.Id, $"User \"{user.Name}\" {FormatEmail(user)}",
                        "umbraco/user-group/save", $"Added user \"{user.Name}\" {FormatEmail(user)} to group {group.Id} \"{group.Name}\" ({group.Alias})");
                }
            }
        }

        private void UserGroupPermissionAssigned(IUserService sender, SaveEventArgs<EntityPermission> saveEventArgs)
        {
            IUser performingUser = CurrentPerformingUser;
            IEnumerable<EntityPermission> perms = saveEventArgs.SavedEntities;
            foreach (EntityPermission perm in perms)
            {
                IUserGroup group = sender.GetUserGroupById(perm.UserGroupId);
                var assigned = string.Join(", ", perm.AssignedPermissions);
                IEntitySlim entity = _entityService.Get(perm.EntityId);

                _auditService.Write(performingUser.Id, $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}", PerformingIp,
                    DateTime.UtcNow,
                    -1, $"User Group {group.Id} \"{group.Name}\" ({group.Alias})",
                    "umbraco/user-group/permissions-change", $"assigning {(string.IsNullOrWhiteSpace(assigned) ? "(nothing)" : assigned)} on id:{perm.EntityId} \"{entity.Name}\"");
            }
        }

        private void OnSavedMember(IMemberService sender, SaveEventArgs<IMember> saveEventArgs)
        {
            IUser performingUser = CurrentPerformingUser;
            IEnumerable<IMember> members = saveEventArgs.SavedEntities;
            foreach (IMember member in members)
            {
                var dp = string.Join(", ", ((Member) member).GetWereDirtyProperties());

                _auditService.Write(performingUser.Id, $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}", PerformingIp,
                    DateTime.UtcNow,
                    -1, $"Member {member.Id} \"{member.Name}\" {FormatEmail(member)}",
                    "umbraco/member/save", $"updating {(string.IsNullOrWhiteSpace(dp) ? "(nothing)" : dp)}");
            }
        }

        private void OnDeletedMember(IMemberService sender, DeleteEventArgs<IMember> deleteEventArgs)
        {
            IUser performingUser = CurrentPerformingUser;
            IEnumerable<IMember> members = deleteEventArgs.DeletedEntities;
            foreach (IMember member in members)
            {
                _auditService.Write(performingUser.Id, $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}", PerformingIp,
                    DateTime.UtcNow,
                    -1, $"Member {member.Id} \"{member.Name}\" {FormatEmail(member)}",
                    "umbraco/member/delete", $"delete member id:{member.Id} \"{member.Name}\" {FormatEmail(member)}");
            }
        }

        private void OnSavedUser(IUserService sender, SaveEventArgs<IUser> saveEventArgs)
        {
            IUser performingUser = CurrentPerformingUser;
            IEnumerable<IUser> affectedUsers = saveEventArgs.SavedEntities;
            foreach (IUser affectedUser in affectedUsers)
            {
                var groups = affectedUser.WasPropertyDirty("Groups")
                    ? string.Join(", ", affectedUser.Groups.Select(x => x.Alias))
                    : null;

                var dp = string.Join(", ", ((User)affectedUser).GetWereDirtyProperties());

                _auditService.Write(performingUser.Id, $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}", PerformingIp,
                    DateTime.UtcNow,
                    affectedUser.Id, $"User \"{affectedUser.Name}\" {FormatEmail(affectedUser)}",
                    "umbraco/user/save", $"updating {(string.IsNullOrWhiteSpace(dp) ? "(nothing)" : dp)}{(groups == null ? "" : "; groups assigned: " + groups)}");
            }
        }

        private void OnDeletedUser(IUserService sender, DeleteEventArgs<IUser> deleteEventArgs)
        {
            IUser performingUser = CurrentPerformingUser;
            IEnumerable<IUser> affectedUsers = deleteEventArgs.DeletedEntities;
            foreach (IUser affectedUser in affectedUsers)
            {
                _auditService.Write(performingUser.Id, $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}", PerformingIp,
                    DateTime.UtcNow,
                    affectedUser.Id, $"User \"{affectedUser.Name}\" {FormatEmail(affectedUser)}",
                    "umbraco/user/delete", "delete user");
            }
        }

        private void WriteAudit(int performingId, int affectedId, string ipAddress, string eventType, string eventDetails, string affectedDetails = null)
        {
            IUser performingUser = _userService.GetUserById(performingId);

            var performingDetails = performingUser == null
                ? $"User UNKNOWN:{performingId}"
                : $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}";

            WriteAudit(performingId, performingDetails, affectedId, ipAddress, eventType, eventDetails, affectedDetails);
        }

        private void WriteAudit(IUser performingUser, int affectedId, string ipAddress, string eventType, string eventDetails)
        {
            var performingDetails = performingUser == null
                ? $"User UNKNOWN"
                : $"User \"{performingUser.Name}\" {FormatEmail(performingUser)}";

            WriteAudit(performingUser?.Id ?? 0, performingDetails, affectedId, ipAddress, eventType, eventDetails);
        }

        private void WriteAudit(int performingId, string performingDetails, int affectedId, string ipAddress, string eventType, string eventDetails, string affectedDetails = null)
        {
            if (affectedDetails == null)
            {
                IUser affectedUser = _userService.GetUserById(affectedId);
                affectedDetails = affectedUser == null
                    ? $"User UNKNOWN:{affectedId}"
                    : $"User \"{affectedUser.Name}\" {FormatEmail(affectedUser)}";
            }

            _auditService.Write(
                performingId,
                performingDetails,
                ipAddress,
                DateTime.UtcNow,
                affectedId,
                affectedDetails,
                eventType,
                eventDetails);
        }
    }
}
