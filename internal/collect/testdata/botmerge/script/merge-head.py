"""Synthetic merge script: merges only when the head commit is approved."""
import argparse
import os

from github import Auth, Github, GithubIntegration

REPO = "acme-app/web"


def client():
    auth = Auth.AppAuth(int(os.environ["APP_ID"]), os.environ["APP_PRIVATE_KEY"])
    gi = GithubIntegration(auth=auth)
    inst = gi.get_repo_installation("acme-app", "web")
    return Github(auth=auth.get_installation_auth(inst.id))


def approved(pr):
    head = pr.head.sha
    approvers = set()
    for review in pr.get_reviews():
        if review.commit_id != head:
            continue
        if review.state == "APPROVED":
            approvers.add(review.user.login)
    return len(approvers) >= 1


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pr", type=int, required=True)
    args = p.parse_args()
    pr = client().get_repo(REPO).get_pull(args.pr)
    if approved(pr):
        pr.merge(merge_method="squash")


if __name__ == "__main__":
    main()
