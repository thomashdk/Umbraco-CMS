using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Umbraco.Core.Security
{

    /// <summary>
    /// A custom user identity for the Umbraco backoffice
    /// </summary>
    [Serializable]
    public class UmbracoBackOfficeIdentity : ClaimsIdentity
    {
        // TODO: Ideally we remove this class and only deal with ClaimsIdentity as a best practice. All things relevant to our own
        // identity are part of claims. This class would essentially become extension methods on a ClaimsIdentity for resolving
        // values from it.
        public static bool FromClaimsIdentity(ClaimsIdentity identity, out UmbracoBackOfficeIdentity backOfficeIdentity)
        {
            // validate that all claims exist
            foreach (var t in RequiredBackOfficeIdentityClaimTypes)
            {
                // if the identity doesn't have the claim, or the claim value is null
                if (identity.HasClaim(x => x.Type == t) == false || identity.HasClaim(x => x.Type == t && x.Value.IsNullOrWhiteSpace()))
                {
                    backOfficeIdentity = null;
                    return false;
                }
            }

            backOfficeIdentity = new UmbracoBackOfficeIdentity(identity);
            return true;
        }

        /// <summary>
        /// Create a back office identity based on an existing claims identity
        /// </summary>
        /// <param name="identity"></param>
        private UmbracoBackOfficeIdentity(ClaimsIdentity identity)
            : base(identity.Claims, Constants.Security.BackOfficeAuthenticationType)
        {
        }

        public const string Issuer = Constants.Security.BackOfficeAuthenticationType;

        /// <summary>
        /// Returns the required claim types for a back office identity
        /// </summary>
        /// <remarks>
        /// This does not include the role claim type or allowed apps type since that is a collection and in theory could be empty
        /// </remarks>
        public static IEnumerable<string> RequiredBackOfficeIdentityClaimTypes => new[]
        {
            ClaimTypes.NameIdentifier, // id
            ClaimTypes.Name,  // username
            ClaimTypes.GivenName,
            Constants.Security.StartContentNodeIdClaimType,
            Constants.Security.StartMediaNodeIdClaimType,
            ClaimTypes.Locality,
            Constants.Security.SecurityStampClaimType
        };

        /// <inheritdoc />
        /// <summary>
        /// Gets the type of authenticated identity.
        /// </summary>
        /// <returns>
        /// The type of authenticated identity. This property always returns "UmbracoBackOffice".
        /// </returns>
        public override string AuthenticationType => Issuer;
    }
}
